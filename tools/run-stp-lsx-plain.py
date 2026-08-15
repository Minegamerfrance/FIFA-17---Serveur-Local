#!/usr/bin/env python3
"""Spawn FIFA + STP LSX plaintext obs on :4216 (decrypt cipher with lsx_crypto)."""
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path

import frida

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from lsx_crypto import LsxSessionTracker  # noqa: E402

SCRIPT_PATH = HERE / "frida-stp-lsx-plain.js"
LOG_DIR = HERE / "versions" / "stp-lsx-plain"


def find_fifa_pid() -> int:
    for p in frida.get_local_device().enumerate_processes():
        if p.name.lower() in ("fifa17.exe", "fifa17"):
            return int(p.pid)
    raise SystemExit("FIFA17.exe not running")


def default_fifa_path() -> Path:
    env = os.environ.get("FIFA17_EXE", "").strip()
    if env:
        return Path(env)
    cand = ROOT.parent / "FIFA 17" / "FIFA17.exe"
    if cand.is_file():
        return cand
    raise SystemExit("set FIFA17_EXE=")


class PlainLogger:
    def __init__(self, log_path: Path, latest: Path) -> None:
        self.log_path = log_path
        self.latest = latest
        self.lines: list[str] = []
        self.tracker = LsxSessionTracker()
        self._xml_re = re.compile(r'xml="((?:\\.|[^"\\])*)"')
        self._hex_re = re.compile(r"\bhex=([0-9a-fA-F]+)")

    def write(self, text: str) -> None:
        print(text)
        self.lines.append(text)
        try:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError:
            pass
        self._enrich(text)

    def _enrich(self, text: str) -> None:
        if "STP_LSX_PLAIN_" in text and "xml=" in text:
            # Frida emits xml=JSON.stringify(...)
            idx = text.find("xml=")
            if idx >= 0:
                try:
                    import json

                    xml = json.loads(text[idx + 4 :])
                    if isinstance(xml, str):
                        self.tracker.on_plaintext(xml)
                except Exception:
                    m = self._xml_re.search(text)
                    if m:
                        xml = bytes(m.group(1), "utf-8").decode("unicode_escape")
                        self.tracker.on_plaintext(xml)
        if "STP_LSX_CIPHER_" in text:
            m = self._hex_re.search(text)
            if not m:
                return
            hx = m.group(1)
            plain = self.tracker.try_decrypt_hex_ascii(hx)
            if not plain:
                return
            direction = "OUT" if "CIPHER_OUT" in text else "IN"
            tag = f"STP_LSX_PLAIN_{direction}"
            # extract fd if present
            fd_m = re.search(r"\bfd=(\d+)", text)
            fd = fd_m.group(1) if fd_m else "?"
            line = (
                f"[stp] ★★★ {tag} mode=DECRYPT fd={fd} via=lsx_crypto "
                f"len={len(plain)} xml={plain!r}"
            )
            print(line)
            self.lines.append(line)
            try:
                with self.log_path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except OSError:
                pass
            self.tracker.on_plaintext(plain)
            # message summary
            inner = re.search(
                r"<(Get[A-Za-z0-9]+|Login|GoOnline|Query[A-Za-z0-9]+|"
                r"GetInternetConnectedState|Challenge\w*)\b",
                plain,
            )
            typ = inner.group(1) if inner else "?"
            summ = (
                f"[stp] ★★★ STP_LSX_MESSAGE mode=DECRYPT type={typ} "
                f"dir={direction.lower()} fd={fd} len={len(plain)}"
            )
            print(summ)
            self.lines.append(summ)
            try:
                with self.log_path.open("a", encoding="utf-8") as f:
                    f.write(summ + "\n")
            except OSError:
                pass

    def flush_latest(self) -> None:
        try:
            self.latest.write_text("\n".join(self.lines) + "\n", encoding="utf-8")
        except OSError:
            pass


def main() -> None:
    mode = os.environ.get("STP_OBS_MODE", "LSX_PLAIN").strip() or "LSX_PLAIN"
    spawn = os.environ.get("STP_OBS_SPAWN", "1").strip() in ("1", "true", "True", "yes")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    log_path = LOG_DIR / f"plain-{mode}-{stamp}.log"
    latest = LOG_DIR / f"latest-{mode}.log"
    logger = PlainLogger(log_path, latest)

    src = f"var STP_OBS_MODE = {mode!r};\n" + SCRIPT_PATH.read_text(encoding="utf-8")
    device = frida.get_local_device()

    if spawn:
        exe = default_fifa_path()
        print(f"[stp] SPAWN {exe} mode={mode}")
        print(f"[stp] log → {log_path}")
        print("[stp] NO pokes. Chronology: ChallengeAccepted → PLAIN/CIPHER → ONLINE")
        pid = device.spawn([str(exe)], cwd=str(exe.parent))
        session = device.attach(pid)
    else:
        pid = find_fifa_pid()
        print(f"[stp] attach pid={pid} mode={mode}")
        session = device.attach(pid)

    script = session.create_script(src)

    def on_message(message, data):  # noqa: ANN001
        if message.get("type") == "error":
            logger.write("[stp] ERROR " + str(message))
        else:
            logger.write(str(message.get("payload", message)))

    def on_log(level, text):  # noqa: ANN001
        logger.write(text.rstrip("\n"))

    script.on("message", on_message)
    try:
        script.set_log_handler(on_log)
    except Exception:
        pass

    script.load()
    if spawn:
        device.resume(pid)
        print(f"[stp] resumed pid={pid}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[stp] detach")
    finally:
        logger.flush_latest()
        try:
            session.detach()
        except Exception:
            pass
        print(f"[stp] wrote {log_path}")
        print(f"[stp] latest → {latest}")


if __name__ == "__main__":
    main()
