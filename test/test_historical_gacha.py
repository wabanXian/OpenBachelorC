from pathlib import Path

import openbachelorc.inject as inject


class Reply:
    def __init__(self, payload):
        self.payload = payload

    def json(self):
        return self.payload


def test_historical_gacha_is_explicitly_disabled_by_default():
    assert inject.prepare_historical_gacha_config("http://server", {}) is None


def test_historical_gacha_requires_matching_binary_and_authenticated_date(monkeypatch):
    dll = Path("X:/isolated/GameAssembly.dll")
    digest = "11" * 32
    monkeypatch.setitem(inject.config, "attach_pc", True)
    monkeypatch.setattr(inject, "_pc_gameassembly_path", lambda: dll)
    monkeypatch.setattr(inject, "_sha256_file", lambda path: digest)
    observed = {}

    def post(url, **kwargs):
        observed["url"] = url
        observed.update(kwargs)
        return Reply({
            "result": 0,
            "mode": "historical",
            "date": "2019-11-20",
            "contentTs": 1574222400,
            "account": "post_tutorial::isolated",
        })

    monkeypatch.setattr(inject.requests, "post", post)
    result = inject.prepare_historical_gacha_config(
        "http://server",
        {
            "enabled": True,
            "account_token": "isolated-token",
            "gameassembly_sha256": digest,
            "client_version": "2.7.81",
            "get_valid_pools_rva": "0x0200df80",
            "timestamp_now_rva": "0x066e08e0",
        },
    )
    assert observed["headers"] == {"secret": "isolated-token"}
    assert result == {
        "content_ts": 1574222400,
        "get_valid_pools_rva": 0x0200DF80,
        "timestamp_now_rva": 0x066E08E0,
        "activate": True,
    }


def test_historical_gacha_safely_disables_on_binary_mismatch(monkeypatch):
    dll = Path("X:/isolated/GameAssembly.dll")
    monkeypatch.setitem(inject.config, "attach_pc", True)
    monkeypatch.setattr(inject, "_pc_gameassembly_path", lambda: dll)
    monkeypatch.setattr(inject, "_sha256_file", lambda path: "11" * 32)
    monkeypatch.setattr(
        inject.requests,
        "post",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("no request")),
    )
    assert inject.prepare_historical_gacha_config(
        "http://server",
        {"enabled": True, "account_token": "x", "gameassembly_sha256": "00"},
    ) is None
