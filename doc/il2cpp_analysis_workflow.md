# Windows IL2CPP reusable analysis workflow

This workflow keeps two deliberately separate caches:

1. A REA snapshot caches exact immutable queries and Evidence. It is not a Ghidra database.
2. A persistent Ghidra project keeps the analyzed `GameAssembly.dll`; incremental queries reopen it with `-process ... -noanalysis`.

Large or proprietary artifacts are stored under ignored `analysis/` and are never committed.

## Prepare a version-bound profile

```powershell
uv run python tools/il2cpp_analysis.py prepare
uv run python tools/il2cpp_analysis.py status
```

The profile key binds the DLL SHA-256, REA version, Ghidra version, analysis mode and seed SHA-256. `dump.cs` RVAs are converted to addresses using the PE image base. A client update therefore creates a different directory instead of silently reusing stale addresses.

REA 6.5.0 does not expose `inspect-il2cpp-metadata`. The copied metadata is only header-checked and hash-bound. Do not claim method linkage came from metadata. When a future installed REA version actually advertises that command, its `--binary` and `--ghidra-seeds` output may replace the `dump.cs` seed source after comparing address coverage.

## REA Snapshot path

For MCP, use `analysis/il2cpp/<dll-sha>/<profile>/rea.snapshot.json`:

1. `open_binary(path=<cached GameAssembly.dll>, provider_id="ghidra", snapshot_path=<snapshot>)` when the snapshot already exists; omit `snapshot_path` on its first creation.
2. Keep that binary session open for all related protocol questions.
3. Reuse existing Evidence before issuing an identical query.
4. Finish with `close_binary(snapshot_path=<snapshot>, overwrite=true)`.

For CLI exact-query replay:

```powershell
uv run python tools/il2cpp_analysis.py rea-query 0x1825c13e0
```

Snapshot replay can still start the Windows Ghidra provider for admission, and a new query can still cold-start analysis. That is why the persistent project exists.

## Persistent Ghidra project

The default profile is `seeded-on-demand`: it imports once, applies seeds and saves without running whole-program default analysis:

```powershell
uv run python tools/il2cpp_analysis.py ghidra-init
```

It imports the cached binary, applies the hash-bound IL2CPP seeds and saves the project. It never passes `-deleteProject`. Whole-program `ghidra-default` remains an explicit opt-in prepare mode; it is not the recommended default for this 218 MB DLL.

Query a new RVA-derived address without reimport or auto-analysis:

```powershell
uv run python tools/il2cpp_analysis.py ghidra-query 0x1825c13e0
```

The first query invokes `analyzeHeadless -process GameAssembly.dll -noanalysis` and writes pseudocode plus the function name, entry point, signature and body ranges beneath the profile's `queries/` directory. Later identical queries validate the output hash and metadata and return that file without starting Ghidra.

The function cache key includes the DLL SHA-256, analysis profile, normalized address, decompiler timeout, exporter-script SHA-256 and an explicit cache revision. Force one function to be decompiled again after changing Ghidra symbols, types or function boundaries with:

```powershell
uv run python tools/il2cpp_analysis.py ghidra-query 0x1825c13e0 --refresh
```

For a deliberate batch of manual analysis changes, pass a stable revision label such as `--cache-revision types-v2`; this creates a separate cache generation. `runs.jsonl` distinguishes `ghidra-query`, `ghidra-query-refresh`, and `ghidra-query-cache-hit`, and records wall time, command and exit status.

## Current-build validation (2026-10-21)

- `GameAssembly.dll` SHA-256: `583b04ff4d1b1a4b35eaf09d77d936408c25447c9e345ef0463d814b6a123fc5`.
- Metadata SHA-256: `d3fede171f92740a6f5dc053c58c7013d3c962db764ad1f05cbe977c074fcd1f`; IL2CPP metadata version 29.
- `dump.cs` produced 246,665 unique method-address seeds. Ghidra applied all seeds with zero failed or unmapped entries.
- Seeded import completed in 237.736 seconds with `-noanalysis`. A whole-program trial was deliberately cancelled and is not part of the reusable profile.
- Separate headless processes reopened the saved project and queried the potential callback in 23.578 seconds, repeated it in 20.303 seconds, and queried a different seeded function in 25.138 seconds. Each run used `-process ... -noanalysis`; none re-imported the DLL or ran whole-program auto-analysis.
- After adding the per-function cache, the first cache population for `0x1825c13e0` started Ghidra and took 34.435 seconds. The immediately repeated query logged `ghidra-query-cache-hit` in 0.013 seconds internally (0.896 seconds including Python startup and manifest hash validation) and did not start Ghidra.
- The REA snapshot was saved and reopened successfully, but its first attempted function query timed out before producing Evidence, so it currently proves snapshot persistence/compatibility only—not an exact-query cache hit.

A truly separate future Codex chat still needs to run `status` followed by one known `ghidra-query` to provide the product-level cross-chat check. The persistent files already survive process exits; do not report that final cross-chat check as completed until it has actually been run.

## Standard protocol investigation order

1. Read request/response types and method RVAs in the matching `dump.cs`.
2. Confirm the current profile's DLL and dump hashes.
3. Search the investigation notes/Evidence before repeating a known query.
4. Use the REA snapshot for an identical previous question.
5. Use the persistent Ghidra project for a new function.
6. Use runtime HTTP/client evidence when static pseudocode cannot establish behavior.
7. Save the REA snapshot at the end of the session.

`addon`, Metadata, and Ghidra output are evidence, not original source. Static analysis does not prove runtime execution.
