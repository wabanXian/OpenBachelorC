# Windows PC historical gacha compatibility

## Scope and evidence

This compatibility layer changes only the timestamp passed by
`Torappu.GachaDB.GetValidPoolsEnumerator()` to its time-list enumerator.  The
current PC `dump.cs` identifies:

- `GachaDB.GetValidPoolsEnumerator`: RVA `0x0200df80`;
- `DateTimeUtil.get_timeStampNow`: RVA `0x066e08e0`;
- `GachaPoolClientData.openTime/endTime`: offsets `0x20/0x28`.

Targeted decompilation of `GetValidPoolsEnumerator` confirms that it calls
`DateTimeUtil.get_timeStampNow()` once and stores that result in the returned
enumerator's `curTs`.  `rel/historical_gacha.js` therefore substitutes the
timestamp only while this method is active on the same thread.  It does not
change `DateTime.Now`, `DateTimeUtil` globally, account `syncData.ts`, AP,
building production, or training clocks.

The implementation is bound to Windows client 2.7.81's recorded
`GameAssembly.dll` SHA-256
`583b04ff4d1b1a4b35eaf09d77d936408c25447c9e345ef0463d814b6a123fc5`.
The launcher disables the shim safely when the hash differs.

## Configuration and local date source

The feature is disabled by default.  Set these values in `conf/config.json`:

```json
"historical_gacha_config": {
  "enabled": true,
  "client_version": "2.7.81",
  "gameassembly_sha256": "583b04ff4d1b1a4b35eaf09d77d936408c25447c9e345ef0463d814b6a123fc5",
  "get_valid_pools_rva": "0x0200df80",
  "timestamp_now_rva": "0x066e08e0"
}
```

At startup the launcher calls the S endpoint
`POST /account/historicalContentDate` over loopback.  No account token or copy
of the game login credential is required.  Both the client filter and S-side
draw authorization read the same server-local configuration.  The S server
listens on loopback and the endpoint additionally rejects non-loopback peers.
Realtime mode, a non-loopback or unreachable server, an invalid timestamp, or
a DLL hash mismatch leaves the original client behaviour untouched.

Changing the date requires logging out and restarting/re-attaching the PC
client.  No recompilation is needed.  A successful attach prints both:

- `historical gacha compatibility loaded date=...`;
- a Frida message from `historical_gacha.js` with `kind: installed`.

## 2019-11-20 manual acceptance

1. Run S-side
   `historical-content-save set-date --date 2019-11-20 --yes`.
2. Enable `historical_gacha_config.enabled` in the C configuration.
3. Start S, then launch C with `--attach_pc`.
4. Open Headhunting.  `NORM_4_0_5` and `NORM_5_0_1` should both appear (plus
   the account's new-player pool when applicable).
5. Open each detail page and verify the advertised rate-up operators.
6. Perform an isolated single pull and ten-pull with sufficient test-account
   currency, then relog and verify currency, operators, guarantee state, and
   shared normal-pool six-star pity persist.
7. Change/reset the S-side date and restart/relog; the list must refresh to the
   newly valid GameData window.

Automated tests cover configuration gating, loopback date retrieval,
binary mismatch shutdown, and JavaScript syntax.  Actual Frida attachment and
the rendered Windows client list remain real-client acceptance items.
