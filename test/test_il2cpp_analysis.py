import importlib.util
import json
import struct
from types import SimpleNamespace
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "tools" / "il2cpp_analysis.py"
SPEC = importlib.util.spec_from_file_location("il2cpp_analysis", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_dump_cs_seeds_are_rva_based_and_deduplicated(tmp_path):
    dump = tmp_path / "dump.cs"
    dump.write_text(
        "class Example.Type : System.Object\n"
        "{\n"
        "    System.Void First(); // 0x00001234\n"
        "    System.Void Alias(); // 0x00001234\n"
        "    System.Void Second(System.Int32 value); // 0x00005678\n"
        "}\n",
        encoding="utf-8",
    )
    output = tmp_path / "seeds.tsv"
    result = MODULE.dump_cs_seeds(dump, 0x180000000, output)
    lines = output.read_text(encoding="utf-8").splitlines()
    assert lines == [
        "0x180001234\tfunction\tExample_Type__First",
        "0x180005678\tfunction\tExample_Type__Second",
    ]
    assert result["functionSeeds"] == 2
    assert result["foldedAddresses"] == 1


def test_metadata_header_recognizes_unity_magic(tmp_path):
    metadata = tmp_path / "global-metadata.dat"
    metadata.write_bytes(struct.pack("<II", MODULE.METADATA_MAGIC, 29))
    assert MODULE.metadata_header(metadata) == {
        "magic": "0xfab11baf",
        "validMagic": True,
        "version": 29,
    }


def test_profile_key_changes_for_every_compatibility_axis():
    base = MODULE.profile_key("dll", "6.5.0", "12.1.2", "seed")
    assert base != MODULE.profile_key("new-dll", "6.5.0", "12.1.2", "seed")
    assert base != MODULE.profile_key("dll", "6.6.0", "12.1.2", "seed")
    assert base != MODULE.profile_key("dll", "6.5.0", "12.1.3", "seed")
    assert base != MODULE.profile_key("dll", "6.5.0", "12.1.2", "new-seed")
    assert base != MODULE.profile_key(
        "dll", "6.5.0", "12.1.2", "seed", "ghidra-default"
    )


def _query_fixture(tmp_path):
    binary = tmp_path / "GameAssembly.dll"
    seeds = tmp_path / "seeds.tsv"
    binary.write_bytes(b"binary")
    seeds.write_text("seed\n", encoding="utf-8")
    manifest = {
        "profileKey": "profile-a",
        "binary": {"cached": str(binary), "sha256": MODULE.sha256(binary)},
        "ghidra": {
            "seeds": str(seeds),
            "seedSha256": MODULE.sha256(seeds),
            "install": str(tmp_path / "ghidra"),
            "projectDirectory": str(tmp_path / "project"),
            "projectName": "project",
            "program": "GameAssembly.dll",
        },
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    args = SimpleNamespace(
        manifest=manifest_path,
        address="0x180001234",
        decompile_timeout=120,
        cache_revision="0",
        refresh=False,
        java_home=tmp_path,
    )
    return args


def test_ghidra_query_uses_disk_cache_without_second_process(tmp_path, monkeypatch):
    args = _query_fixture(tmp_path)
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        script = command.index("ExportFunction.java")
        Path(command[script + 2]).write_text("complete pseudocode\n", encoding="utf-8")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)
    assert MODULE.ghidra_query(args) == 0
    assert len(calls) == 1
    assert MODULE.ghidra_query(args) == 0
    assert len(calls) == 1
    runs = [json.loads(line) for line in (tmp_path / "runs.jsonl").read_text().splitlines()]
    assert runs[-1]["operation"] == "ghidra-query-cache-hit"
    assert runs[-1]["command"][0] == "disk-cache"


def test_ghidra_query_refresh_restarts_process(tmp_path, monkeypatch):
    args = _query_fixture(tmp_path)
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        script = command.index("ExportFunction.java")
        Path(command[script + 2]).write_text(f"result {len(calls)}\n", encoding="utf-8")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)
    assert MODULE.ghidra_query(args) == 0
    args.refresh = True
    assert MODULE.ghidra_query(args) == 0
    assert len(calls) == 2


def test_query_cache_key_covers_options_and_revision(tmp_path):
    args = _query_fixture(tmp_path)
    _, manifest = MODULE.load_manifest(args.manifest)
    first = MODULE.ghidra_query_cache(args.manifest, manifest, args.address, 120, "0")
    timeout = MODULE.ghidra_query_cache(args.manifest, manifest, args.address, 60, "0")
    revision = MODULE.ghidra_query_cache(args.manifest, manifest, args.address, 120, "types-v2")
    assert first["key"] != timeout["key"]
    assert first["key"] != revision["key"]
