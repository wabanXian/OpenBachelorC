"""Version-bound REA snapshot and persistent Ghidra workflow for PC IL2CPP.

The large binary, metadata, snapshots, and Ghidra database live below the
ignored analysis root.  The checked-in code only describes and validates the
workflow; it never modifies the game installation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path


DEFAULT_GAME = Path(r"I:\BaiduNetdiskDownload\Hypergryph Launcher\games\Arknights")
DEFAULT_DUMP = Path("dump/pc/20261019_144647_unknown/dump.cs")
DEFAULT_ROOT = Path("analysis/il2cpp")
DEFAULT_GHIDRA = Path(r"D:\BaiduNetdiskDownload\ghidra_12.1.2_PUBLIC")
DEFAULT_REA_ROOT = Path(
    r"C:\Users\nyochio\AppData\Local\npm-cache\_npx\ad9a3fdbcad992c6"
    r"\node_modules\rea-agents"
)
DEFAULT_JAVA_HOME = Path(r"C:\Program Files\Java\jdk-24")
METADATA_MAGIC = 0xFAB11BAF
GHIDRA_QUERY_CACHE_SCHEMA = 1


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pe_image_base(path: Path) -> int:
    with path.open("rb") as stream:
        stream.seek(0x3C)
        pe_offset = struct.unpack("<I", stream.read(4))[0]
        stream.seek(pe_offset)
        if stream.read(4) != b"PE\0\0":
            raise ValueError("not a PE image")
        stream.seek(20, 1)
        optional = stream.tell()
        magic = struct.unpack("<H", stream.read(2))[0]
        if magic == 0x20B:
            stream.seek(optional + 24)
            return struct.unpack("<Q", stream.read(8))[0]
        if magic == 0x10B:
            stream.seek(optional + 28)
            return struct.unpack("<I", stream.read(4))[0]
        raise ValueError(f"unsupported PE optional-header magic: 0x{magic:x}")


def metadata_header(path: Path) -> dict:
    with path.open("rb") as stream:
        magic, version = struct.unpack("<II", stream.read(8))
    return {"magic": f"0x{magic:08x}", "validMagic": magic == METADATA_MAGIC, "version": version}


def safe_symbol(value: str) -> str:
    value = value.replace(".", "_").replace("$", "_")
    return re.sub(r"[^A-Za-z0-9_]", "_", value).strip("_") or "il2cpp_method"


def dump_cs_seeds(dump_cs: Path, image_base: int, destination: Path) -> dict:
    class_name = "Global"
    by_address: dict[int, list[str]] = {}
    class_re = re.compile(r"^(?:class|struct|interface)\s+([^\s:{]+)")
    method_re = re.compile(r"^\s*.*?([^\s(]+)\([^;]*\);\s*//\s*0x([0-9a-fA-F]+)\s*$")
    with dump_cs.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            class_match = class_re.match(line)
            if class_match:
                class_name = class_match.group(1)
                continue
            match = method_re.match(line)
            if not match:
                continue
            rva = int(match.group(2), 16)
            if not rva:
                continue
            address = image_base + rva
            name = safe_symbol(f"{class_name}__{match.group(1)}")
            by_address.setdefault(address, []).append(name)
    lines = []
    folded = 0
    for address, names in sorted(by_address.items()):
        unique = list(dict.fromkeys(names))
        lines.append(f"0x{address:x}\tfunction\t{unique[0]}")
        if len(unique) > 1:
            folded += 1
    destination.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return {"functionSeeds": len(lines), "foldedAddresses": folded, "seedSha256": sha256(destination)}


def profile_key(
    dll_hash: str,
    rea_version: str,
    ghidra_version: str,
    seed_hash: str,
    analysis_mode: str = "seeded-on-demand",
) -> str:
    payload = json.dumps(
        {
            "dllSha256": dll_hash,
            "reaVersion": rea_version,
            "ghidraVersion": ghidra_version,
            "provider": "ghidra",
            "analyzerProfile": analysis_mode,
            "seedSha256": seed_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()[:16]


def prepare(args) -> Path:
    game = args.game_dir.resolve()
    dll = game / "GameAssembly.dll"
    metadata = game / "Arknights_Data/il2cpp_data/Metadata/global-metadata.dat"
    dump_cs = args.dump_cs.resolve()
    for required in (dll, metadata, dump_cs):
        if not required.is_file():
            raise FileNotFoundError(required)
    dll_hash, metadata_hash, dump_hash = sha256(dll), sha256(metadata), sha256(dump_cs)
    image_base = pe_image_base(dll)
    staging = args.root.resolve() / dll_hash
    staging.mkdir(parents=True, exist_ok=True)
    seed_tmp = staging / "dump-cs-seeds.tsv"
    seed_info = dump_cs_seeds(dump_cs, image_base, seed_tmp)
    key = profile_key(
        dll_hash,
        args.rea_version,
        args.ghidra_version,
        seed_info["seedSha256"],
        args.analysis_mode,
    )
    profile = staging / key
    profile.mkdir(parents=True, exist_ok=True)
    seeds = profile / "ghidra-seeds.tsv"
    if seeds != seed_tmp:
        shutil.copy2(seed_tmp, seeds)
    target = profile / "GameAssembly.dll"
    meta_copy = profile / "global-metadata.dat"
    if not target.is_file() or sha256(target) != dll_hash:
        shutil.copy2(dll, target)
    if not meta_copy.is_file() or sha256(meta_copy) != metadata_hash:
        shutil.copy2(metadata, meta_copy)
    manifest = {
        "schema": 1,
        "profileKey": key,
        "gameDirectory": str(game),
        "binary": {"source": str(dll), "cached": str(target), "sha256": dll_hash, "imageBase": f"0x{image_base:x}"},
        "metadata": {"source": str(metadata), "cached": str(meta_copy), "sha256": metadata_hash, **metadata_header(metadata)},
        "dumpCs": {"path": str(dump_cs), "sha256": dump_hash},
        "rea": {"version": args.rea_version, "snapshot": str(profile / "rea.snapshot.json")},
        "ghidra": {
            "version": args.ghidra_version,
            "install": str(args.ghidra.resolve()),
            "projectDirectory": str(profile / "ghidra-project"),
            "projectName": f"Arknights_{dll_hash[:12]}",
            "program": "GameAssembly.dll",
            "analysisMode": args.analysis_mode,
            "seeds": str(seeds),
            **seed_info,
        },
    }
    (profile / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (args.root.resolve() / "current.json").write_text(
        json.dumps({"manifest": str(profile / "manifest.json")}, indent=2), encoding="utf-8"
    )
    print(profile / "manifest.json")
    return profile / "manifest.json"


def load_manifest(path: Path) -> tuple[Path, dict]:
    if path.name == "current.json":
        path = Path(json.loads(path.read_text(encoding="utf-8"))["manifest"])
    value = json.loads(path.read_text(encoding="utf-8"))
    binary = Path(value["binary"]["cached"])
    if sha256(binary) != value["binary"]["sha256"]:
        raise RuntimeError("cached GameAssembly.dll hash no longer matches manifest")
    seeds = Path(value["ghidra"]["seeds"])
    if sha256(seeds) != value["ghidra"]["seedSha256"]:
        raise RuntimeError("Ghidra seed hash no longer matches manifest")
    return path, value


def log_run(manifest_path: Path, operation: str, started: float, command: list[str], code: int) -> None:
    row = {
        "operation": operation,
        "startedUnix": started,
        "elapsedSeconds": round(time.time() - started, 3),
        "exitCode": code,
        "command": command,
    }
    with (manifest_path.parent / "runs.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(row) + "\n")


def ghidra_environment(java_home: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["JAVA_HOME"] = str(java_home.resolve())
    return env


def normalized_address(value: str) -> str:
    return f"0x{int(value, 0):x}"


def ghidra_query_cache(
    manifest_path: Path,
    manifest: dict,
    address: str,
    decompile_timeout: int,
    cache_revision: str,
) -> dict:
    exporter = (Path(__file__).parent / "ghidra" / "ExportFunction.java").resolve()
    address = normalized_address(address)
    inputs = {
        "schema": GHIDRA_QUERY_CACHE_SCHEMA,
        "binarySha256": manifest["binary"]["sha256"],
        "profileKey": manifest["profileKey"],
        "address": address,
        "decompileTimeoutSeconds": decompile_timeout,
        "cacheRevision": cache_revision,
        "exporterSha256": sha256(exporter),
    }
    key = hashlib.sha256(
        json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    stem = f"{address[2:]}-{key[:16]}"
    directory = manifest_path.parent / "queries"
    return {
        "key": key,
        "inputs": inputs,
        "output": directory / f"{stem}.txt",
        "metadata": directory / f"{stem}.json",
        "exporter": exporter,
    }


def valid_ghidra_query_cache(cache: dict) -> bool:
    output, metadata = cache["output"], cache["metadata"]
    if not output.is_file() or not metadata.is_file():
        return False
    try:
        value = json.loads(metadata.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        value.get("cacheKey") == cache["key"]
        and value.get("inputs") == cache["inputs"]
        and value.get("outputSha256") == sha256(output)
    )


def ghidra_init(args) -> int:
    manifest_path, value = load_manifest(args.manifest.resolve())
    project = Path(value["ghidra"]["projectDirectory"])
    project.mkdir(parents=True, exist_ok=True)
    gpr = project / f'{value["ghidra"]["projectName"]}.gpr'
    if gpr.exists():
        print(f"persistent project already exists: {gpr}")
        return 0
    headless = Path(value["ghidra"]["install"]) / "support/analyzeHeadless.bat"
    seed_script = args.rea_root.resolve() / "bridge/ghidra"
    command = [
        str(headless), str(project), value["ghidra"]["projectName"],
        "-import", value["binary"]["cached"],
        "-scriptPath", str(seed_script),
        "-preScript", "ReaGhidraApplySeeds.java", value["ghidra"]["seeds"],
    ]
    if value["ghidra"]["analysisMode"] == "seeded-on-demand":
        command.append("-noanalysis")
    else:
        command.extend(["-analysisTimeoutPerFile", str(args.timeout)])
    started = time.time()
    code = subprocess.run(command, env=ghidra_environment(args.java_home), check=False).returncode
    log_run(manifest_path, "ghidra-init", started, command, code)
    return code


def ghidra_query(args) -> int:
    manifest_path, value = load_manifest(args.manifest.resolve())
    cache = ghidra_query_cache(
        manifest_path,
        value,
        args.address,
        args.decompile_timeout,
        args.cache_revision,
    )
    output = cache["output"]
    output.parent.mkdir(exist_ok=True)
    started = time.time()
    if not args.refresh and valid_ghidra_query_cache(cache):
        log_run(
            manifest_path,
            "ghidra-query-cache-hit",
            started,
            ["disk-cache", cache["key"]],
            0,
        )
        print(f"cache hit: {output}")
        return 0

    cache["metadata"].unlink(missing_ok=True)
    headless = Path(value["ghidra"]["install"]) / "support/analyzeHeadless.bat"
    command = [
        str(headless), value["ghidra"]["projectDirectory"], value["ghidra"]["projectName"],
        "-process", value["ghidra"]["program"], "-noanalysis",
        "-scriptPath", str(cache["exporter"].parent),
        "-postScript", "ExportFunction.java", cache["inputs"]["address"], str(output),
        str(args.decompile_timeout),
    ]
    code = subprocess.run(command, env=ghidra_environment(args.java_home), check=False).returncode
    operation = "ghidra-query-refresh" if args.refresh else "ghidra-query"
    log_run(manifest_path, operation, started, command, code)
    if code == 0 and output.is_file() and output.stat().st_size:
        metadata = {
            "cacheKey": cache["key"],
            "inputs": cache["inputs"],
            "output": str(output),
            "outputSha256": sha256(output),
            "createdUnix": time.time(),
        }
        temporary = cache["metadata"].with_suffix(".json.tmp")
        temporary.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        temporary.replace(cache["metadata"])
        print(output)
    return code


def rea_query(args) -> int:
    manifest_path, value = load_manifest(args.manifest.resolve())
    rea = args.rea_root.resolve() / "scripts/rea.mjs"
    command = [
        "node", str(rea), "function", value["binary"]["cached"], args.address,
        "--provider", "ghidra", "--snapshot", value["rea"]["snapshot"], "--json",
    ]
    env = os.environ.copy()
    env["REA_GHIDRA_SEED_FILE"] = value["ghidra"]["seeds"]
    started = time.time()
    code = subprocess.run(command, env=env, check=False).returncode
    log_run(manifest_path, "rea-query", started, command, code)
    return code


def status(args) -> int:
    manifest_path, value = load_manifest(args.manifest.resolve())
    project = Path(value["ghidra"]["projectDirectory"]) / f'{value["ghidra"]["projectName"]}.gpr'
    report = {
        "manifest": str(manifest_path),
        "profileKey": value["profileKey"],
        "binarySha256": value["binary"]["sha256"],
        "metadataSha256": value["metadata"]["sha256"],
        "metadataVersion": value["metadata"]["version"],
        "reaSnapshotExists": Path(value["rea"]["snapshot"]).is_file(),
        "ghidraProjectExists": project.is_file(),
        "functionSeeds": value["ghidra"]["functionSeeds"],
    }
    print(json.dumps(report, indent=2))
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    sub = result.add_subparsers(dest="command", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--game-dir", type=Path, default=DEFAULT_GAME)
    prep.add_argument("--dump-cs", type=Path, default=DEFAULT_DUMP)
    prep.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    prep.add_argument("--ghidra", type=Path, default=DEFAULT_GHIDRA)
    prep.add_argument("--ghidra-version", default="12.1.2")
    prep.add_argument("--rea-version", default="6.5.0")
    prep.add_argument(
        "--analysis-mode",
        choices=("seeded-on-demand", "ghidra-default"),
        default="seeded-on-demand",
    )
    prep.set_defaults(run=prepare)
    for name, func in (("ghidra-init", ghidra_init), ("ghidra-query", ghidra_query), ("rea-query", rea_query), ("status", status)):
        command = sub.add_parser(name)
        command.add_argument("--manifest", type=Path, default=DEFAULT_ROOT / "current.json")
        if name in {"ghidra-init", "rea-query"}:
            command.add_argument("--rea-root", type=Path, default=DEFAULT_REA_ROOT)
        if name in {"ghidra-init", "ghidra-query"}:
            command.add_argument("--java-home", type=Path, default=DEFAULT_JAVA_HOME)
        if name in {"ghidra-query", "rea-query"}:
            command.add_argument("address")
        if name == "ghidra-query":
            command.add_argument("--decompile-timeout", type=int, default=120)
            command.add_argument(
                "--cache-revision",
                default="0",
                help="bump after manual Ghidra symbol/type/function changes",
            )
            command.add_argument("--refresh", action="store_true")
        if name == "ghidra-init":
            command.add_argument("--timeout", type=int, default=7200)
        command.set_defaults(run=func)
    return result


def main() -> int:
    args = parser().parse_args()
    result = args.run(args)
    return result if isinstance(result, int) else 0


if __name__ == "__main__":
    sys.exit(main())
