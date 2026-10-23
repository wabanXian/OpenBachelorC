import os
import time
import subprocess
import json
import hashlib
from pathlib import Path

import frida
import requests

from .const import PACKAGE_NAME
from .config import config
from .adb import start_apk

SCRIPT_DIRPATH = "rel/"

JAVA_SCRIPT_FILEPATH = os.path.join(SCRIPT_DIRPATH, "java.js")
NATIVE_SCRIPT_FILEPATH = os.path.join(SCRIPT_DIRPATH, "native.js")
EXTRA_SCRIPT_FILEPATH = os.path.join(SCRIPT_DIRPATH, "extra.js")
TRAINER_SCRIPT_FILEPATH = os.path.join(SCRIPT_DIRPATH, "trainer.js")
HISTORICAL_GACHA_SCRIPT_FILEPATH = os.path.join(
    SCRIPT_DIRPATH, "historical_gacha.js"
)


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _pc_gameassembly_path():
    from .pc_const import AK_EXE_FILEPATH_TXT_FILEPATH

    exe_path = Path(AK_EXE_FILEPATH_TXT_FILEPATH).read_text(
        encoding="utf-8"
    ).strip().strip('"')
    return Path(exe_path).parent / "GameAssembly.dll"


def prepare_historical_gacha_config(proxy_url, historical_config):
    """Authenticate and version-check the optional, gacha-only PC shim."""
    if not historical_config.get("enabled", False):
        return None
    if not config.get("attach_pc", False):
        print("warn: historical gacha compatibility is PC-only; disabled")
        return None

    dll_path = _pc_gameassembly_path()
    expected_hash = historical_config.get("gameassembly_sha256", "").lower()
    actual_hash = _sha256_file(dll_path).lower()
    if not expected_hash or actual_hash != expected_hash:
        print(
            "warn: historical gacha compatibility disabled: "
            f"GameAssembly.dll mismatch ({actual_hash})"
        )
        return None

    token = historical_config.get("account_token")
    if not token:
        print("warn: historical gacha compatibility disabled: account_token missing")
        return None
    try:
        result = requests.post(
            f"{proxy_url}/account/historicalContentDate",
            headers={"secret": token},
            json={},
            proxies={"http": "", "https": ""},
            timeout=5,
        ).json()
    except Exception as exc:
        print(f"warn: historical gacha compatibility disabled: date query failed: {exc}")
        return None
    if result.get("result") != 0 or result.get("mode") != "historical":
        print("info: account uses realtime content date; historical gacha shim disabled")
        return None
    timestamp = result.get("contentTs")
    if not isinstance(timestamp, int) or timestamp <= 0:
        print("warn: historical gacha compatibility disabled: invalid content timestamp")
        return None

    print(
        "info: historical gacha compatibility authenticated "
        f"account={result.get('account')} date={result.get('date')} "
        f"client={historical_config.get('client_version')}"
    )
    return {
        "content_ts": timestamp,
        "get_valid_pools_rva": int(
            historical_config.get("get_valid_pools_rva", "0x0200df80"), 0
        ),
        "timestamp_now_rva": int(
            historical_config.get("timestamp_now_rva", "0x066e08e0"), 0
        ),
        "activate": True,
    }


def test_remote_port():
    try:
        requests.get(
            "http://127.0.0.1:27042",
            proxies={"http": "", "https": ""},
            timeout=1,
        )
        return True
    except Exception:
        return False


def handle_script_message(script_filepath, message, data):
    print(f"message [{os.path.basename(script_filepath)}]:", message)


def load_script(device, pid, script_filepath, script_config, is_emulated_realm=False):
    if is_emulated_realm:
        session = device.attach(pid, realm="emulated")
    else:
        session = device.attach(pid)

    with open(script_filepath, encoding="utf-8") as f:
        script_str = f.read()
    script = session.create_script(script_str)
    script.on(
        "message",
        lambda message, data: handle_script_message(script_filepath, message, data),
    )
    script.load()

    for k, v in script_config.items():
        script.post({"type": "conf", "k": k, "v": v})

    return script


class Game:
    def __init__(
        self, device, pid, java_script, native_script, extra_script, trainer_script,
        historical_gacha_script=None,
    ):
        self.device = device
        self.pid = pid
        self.java_script = java_script
        self.native_script = native_script
        self.extra_script = extra_script
        self.trainer_script = trainer_script
        self.historical_gacha_script = historical_gacha_script

    def exec_trainer_command(self, trainer_command_name):
        if self.trainer_script is not None:
            self.trainer_script.post(
                {"type": "conf", "k": "invoke", "v": trainer_command_name}
            )
        else:
            print("err: trainer is disabled")


def test_remote_port_loop():
    for _ in range(100):
        if test_remote_port():
            break
        else:
            time.sleep(0.1)


def attach_pc_game():
    pid = "Gadget"

    test_remote_port_loop()

    device = frida.get_remote_device()

    return device, pid


def start_game_in_emulator(emulator_id):
    if config["use_gadget"]:
        start_apk(emulator_id)
        pid = "Gadget"

    test_remote_port_loop()

    device = frida.get_remote_device()

    if not config["use_gadget"]:
        if config["no_spawn"]:
            start_apk(emulator_id)
            for proc in device.enumerate_processes():
                if (
                    proc.name.lower().find("arknights") >= 0
                    or proc.name.find("明日方舟") >= 0
                ):
                    pid = proc.name
                    break
        else:
            pid = device.spawn(PACKAGE_NAME)

    return device, pid


def start_game(emulator_id):
    if config["attach_pc"]:
        device, pid = attach_pc_game()
    else:
        device, pid = start_game_in_emulator(emulator_id)

    host = config["host"]
    port = config["port"]
    proxy_url = f"http://{host}:{port}"

    is_emulated_realm = config["use_emulated_realm"]

    java_script = load_script(
        device,
        pid,
        JAVA_SCRIPT_FILEPATH,
        {"proxy_url": proxy_url, "no_proxy": config["no_proxy"]},
    )
    native_script = load_script(
        device,
        pid,
        NATIVE_SCRIPT_FILEPATH,
        {
            "proxy_url": proxy_url,
            "no_proxy": config["no_proxy"],
            "native_delay": config["native_delay"],
        },
        is_emulated_realm=is_emulated_realm,
    )

    extra_script = None
    if config["enable_extra"]:
        extra_script = load_script(
            device,
            pid,
            EXTRA_SCRIPT_FILEPATH,
            config["extra_config"],
            is_emulated_realm=is_emulated_realm,
        )

    trainer_script = None
    if config["enable_trainer"]:
        trainer_script = load_script(
            device,
            pid,
            TRAINER_SCRIPT_FILEPATH,
            config["trainer_config"],
            is_emulated_realm=is_emulated_realm,
        )

    historical_gacha_script = None
    historical_script_config = prepare_historical_gacha_config(
        proxy_url, config.get("historical_gacha_config", {})
    )
    if historical_script_config is not None:
        historical_gacha_script = load_script(
            device,
            pid,
            HISTORICAL_GACHA_SCRIPT_FILEPATH,
            historical_script_config,
            is_emulated_realm=is_emulated_realm,
        )

    if not config["attach_pc"]:
        if not config["no_spawn"]:
            device.resume(pid)

    game = Game(
        device, pid, java_script, native_script, extra_script, trainer_script,
        historical_gacha_script,
    )

    return game
