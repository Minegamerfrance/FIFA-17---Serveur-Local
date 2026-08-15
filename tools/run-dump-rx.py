"""Attach Frida dump-rx script to FIFA17.exe; exit when dump completes."""
from __future__ import annotations

import sys
import time
from pathlib import Path

import frida

HERE = Path(__file__).resolve().parent
SCRIPT = HERE / "frida-dump-rx.js"
OUT = HERE / "dump"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    # Clear previous bin chunks so xref does not mix dumps.
    for p in OUT.glob("rx-*.bin"):
        p.unlink(missing_ok=True)
    for p in OUT.glob("rd-*.bin"):
        p.unlink(missing_ok=True)

    out_abs = str(OUT.resolve()).replace("\\", "/")
    code = SCRIPT.read_text(encoding="utf-8").replace("__OUT_DIR__", out_abs)

    device = frida.get_local_device()
    try:
        session = device.attach("FIFA17.exe")
    except frida.ProcessNotFoundError:
        print("FIFA17.exe not found — open FIFA first", file=sys.stderr)
        return 1

    done = {"ok": False, "err": None}

    def on_msg(message, data):
        if message["type"] == "send":
            payload = message.get("payload")
            print(payload)
            if isinstance(payload, dict) and payload.get("type") == "done":
                done["ok"] = True
            if isinstance(payload, dict) and payload.get("type") == "error":
                done["err"] = payload.get("error")
        elif message["type"] == "error":
            print(message.get("description") or message, file=sys.stderr)
            if message.get("stack"):
                print(message["stack"], file=sys.stderr)
            done["err"] = message.get("description") or str(message)
        else:
            print(message)

    script = session.create_script(code)
    script.on("message", on_msg)
    script.load()
    print(f"Dump -> {out_abs}")

    # Wait for DONE (or timeout ~10 min for ~100–200 MB).
    deadline = time.time() + 600
    try:
        while time.time() < deadline:
            if done["ok"]:
                break
            if done["err"]:
                break
            time.sleep(0.5)
        else:
            print("timeout waiting for dump", file=sys.stderr)
            session.detach()
            return 2
    except KeyboardInterrupt:
        print("detaching")
        session.detach()
        return 130

    session.detach()
    if done["err"] and not done["ok"]:
        print(f"dump error: {done['err']}", file=sys.stderr)
        return 3
    print("dump complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
