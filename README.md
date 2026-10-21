# OpenBachelorC

OpenBachelor Client. For PvZ Online.

This project is a game launcher only. If you are looking for a game server, please look at OpenBachelor Server.

## Supported Environment

A rooted arm64 android phone.

A jailed arm64 android phone (with OpenBachelorG).

MUMU 12 (with OpenBachelorG MUMU build).

Mac (Apple silicon) with AVD (Android Studio) (recommended: arm64, Android 15, Google APIs Image).

> FYI: For AVD users, do not use Google Play Store image, which is not readily rooted.

Windows PC (Experimental).

## How-To for Android

### 0. Start Server

1. Use a game server, preferably OpenBachelor Server.

### 1. Setup Client

1. Install Python 3.12 and add `python.exe` to path.

2. Run `setup.cmd`.

3. Open your emulator/phone's settings, enable its root permission and adb connection.

4. Run `load_config_[YOUR_DEVICE].cmd`. For example, if you are using a jailed phone (no root permission), run `load_config_jailed_phone.cmd`.

### 2. Run Client

1. Run `main.cmd`.

## How-To for Windows PC (Experimental)

### 0. Start Server

1. Use a game server, preferably OpenBachelor Server.

### 1. Setup Client

1. Install Python 3.12 and add `python.exe` to path.

2. Run `setup.cmd`.

### 2. Patch Game

1. Run `setup_pc.cmd`.

### 3. Run Client

1. Run `main_attach_pc.cmd`.

### 4. Restore Game

1. Run `unset_pc.cmd`.

### Optional: collect PC IL2CPP runtime dumps

This is disabled by default and uses the existing Trainer build. Start the PC
client explicitly with:

```cmd
.\main-uv.cmd --attach_pc --dump_json
```

`--dump_json` enables runtime game-database JSON export only. At the Trainer
prompt, run `!dump` to ask the bundled `frida-il2cpp-bridge` code to write
`dump.cs`. After the game has finished writing the files, run:

```text
?collect_pc_dump
```

The command copies existing files from Unity's Windows `persistentDataPath`
into a new timestamped directory under `dump/pc/`. It also writes
`manifest.json` with client versions found in `Player.log`, hashes for
`Arknights.exe` and `GameAssembly.dll`, export hashes, and capability notes.
Existing archives are never overwritten.

The generated method addresses in `dump.cs` are RVAs relative to the recorded
`GameAssembly.dll`. The Trainer does not export or decrypt
`global-metadata.dat`; `manifest.json` records that limitation explicitly.

For repeatable REA/Ghidra investigation of a collected PC build, see
[`doc/il2cpp_analysis_workflow.md`](doc/il2cpp_analysis_workflow.md). The
default workflow uses a persistent, IL2CPP-seeded Ghidra project and does not
run whole-program auto-analysis.
