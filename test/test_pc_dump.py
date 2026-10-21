import json
from pathlib import Path

from openbachelorc.dump import collect_pc_dump


def test_collect_pc_dump_archives_without_overwriting(tmp_path):
    source = tmp_path / "LocalLow" / "Hypergryph" / "Arknights"
    source.mkdir(parents=True)
    (source / "dump.cs").write_text(
        "void Example(); // 0x00123456\n", encoding="utf-8"
    )
    (source / "CharacterDB.json").write_text(
        '{"characters":{"char_001":{"name":"A"}}}', encoding="utf-8"
    )
    (source / "Player.log").write_text(
        'body={"clientVersion":"2.7.81","assetsVersion":"asset-1",'
        '"udtVersion":"78.0.0"}',
        encoding="utf-8",
    )
    game_dir = tmp_path / "game"
    game_dir.mkdir()
    exe = game_dir / "Arknights.exe"
    exe.write_bytes(b"exe")
    (game_dir / "GameAssembly.dll").write_bytes(b"assembly")
    output = tmp_path / "output"

    first = collect_pc_dump(exe, source, output)
    second = collect_pc_dump(exe, source, output)

    assert first != second
    assert (first / "dump.cs").read_text(encoding="utf-8").endswith(
        "0x00123456\n"
    )
    assert json.loads((first / "character_table.json").read_text(encoding="utf-8"))
    manifest = json.loads((first / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["versions"] == {
        "clientVersion": "2.7.81",
        "assetsVersion": "asset-1",
        "udtVersion": "78.0.0",
    }
    assert manifest["modules"]["GameAssembly.dll"]["sha256"]
    assert manifest["capabilities"] == {
        "dumpCs": True,
        "runtimeJson": True,
        "decryptedGlobalMetadata": False,
    }


def test_collect_pc_dump_does_not_invent_missing_exports(tmp_path):
    source = tmp_path / "empty"
    source.mkdir()

    assert collect_pc_dump(source_dir=source, dump_dirpath=tmp_path / "out") is None
    assert not (tmp_path / "out").exists()
