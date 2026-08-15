"""Attach Frida SSL bypass to FIFA17.exe. Run after FIFA is launched and npm start is up.

Also tees all console output to tools/versions/<CURRENT>/frida.log
"""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import frida

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SCRIPT = (HERE / "frida-ssl-bypass.js").read_text(encoding="utf-8")
VERSIONS = HERE / "versions"


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, data):
        for s in self.streams:
            try:
                s.write(data)
                s.flush()
            except Exception:
                pass
        return len(data)

    def flush(self):
        for s in self.streams:
            try:
                s.flush()
            except Exception:
                pass


def current_version_dir() -> Path:
    cur = "v29"
    cur_file = VERSIONS / "CURRENT.txt"
    if cur_file.exists():
        cur = cur_file.read_text(encoding="utf-8").strip().splitlines()[0].strip() or cur
    d = VERSIONS / cur
    d.mkdir(parents=True, exist_ok=True)
    return d


def main() -> int:
    vdir = current_version_dir()
    log_path = vdir / "frida.log"
    log_f = open(log_path, "w", encoding="utf-8", newline="\n")
    sys.stdout = Tee(sys.__stdout__, log_f)
    sys.stderr = Tee(sys.__stderr__, log_f)

    print(f"=== frida log → {log_path} ===")
    print(f"=== {datetime.now(timezone.utc).isoformat()} ===")

    device = frida.get_local_device()
    spawn_exe = os.environ.get("FIFA_SPAWN_EXE", "").strip()
    spawned = False
    target_pid_text = os.environ.get("FIFA_TARGET_PID", "").strip()
    if spawn_exe:
        exe = Path(spawn_exe)
        if not exe.is_file():
            print(f"FATAL: FIFA_SPAWN_EXE not found: {exe}")
            return 1
        spawn_argv = [str(exe)]
        frost_mod_data = exe.parent / "ModData"
        if frost_mod_data.is_dir():
            # Frosty deploys modified bundles under ModData. Keep the unique
            # suspended Frida launch, but make FIFA load the deployed mod.
            spawn_argv.extend(["-dataPath", str(frost_mod_data)])
            print(f"Frosty ModData enabled: {frost_mod_data}")
        pid = device.spawn(spawn_argv, cwd=str(exe.parent))
        spawned = True
        print(f"Spawned suspended FIFA17.exe pid={pid}")
    elif target_pid_text:
        procs = [p for p in device.enumerate_processes() if p.name.lower() == "fifa17.exe"]
        try:
            target_pid = int(target_pid_text)
        except ValueError:
            print(f"FATAL: invalid FIFA_TARGET_PID={target_pid_text!r}")
            return 1
        matching = [p for p in procs if p.pid == target_pid]
        if not matching:
            print(f"FATAL: FIFA_TARGET_PID={target_pid} is not a live FIFA17.exe")
            return 1
        pid = target_pid
    else:
        while True:
            procs = [p for p in device.enumerate_processes() if p.name.lower() == "fifa17.exe"]
            if procs:
                break
            print("Waiting for FIFA17.exe … (lance le jeu)")
            time.sleep(2)
        pid = max(p.pid for p in procs)
    print(f"Attaching to FIFA17.exe pid={pid} exact={int(bool(target_pid_text) or spawned)}")
    session = device.attach(pid)
    auto_detach_requested = {"value": False, "reason": ""}

    def on_msg(message, _data):
        t = message.get("type")
        if t == "send":
            payload = message["payload"]
            print(payload)
            if isinstance(payload, dict) and payload.get("event") == "AUTO_DETACH_AFTER_LOGIN":
                auto_detach_requested["value"] = True
                auto_detach_requested["reason"] = str(payload.get("reason", ""))
        elif t == "log":
            # Frida console.log from JS
            print(message.get("payload", message))
        elif t == "error":
            print(message.get("stack") or message)
        else:
            print(message)

    # FIFA 14 Local FUT's stable launcher uses one Frida session for the whole
    # gameplay process.  FIFA 17 previously attached a second Python runner for
    # LSX, which raced this session and could terminate the game/session.  Load
    # the LSX bridge into this existing session instead.
    stp_script = None
    stp_script_path = os.environ.get("STP_FRIDA_SCRIPT", "").strip()
    if stp_script_path:
        stp_path = Path(stp_script_path)
        if not stp_path.is_file():
            print(f"FATAL: STP_FRIDA_SCRIPT not found: {stp_path}")
            return 1
        stp_script = session.create_script(stp_path.read_text(encoding="utf-8"))
        stp_script.on("message", on_msg)
        stp_script.load()
        print(f"SINGLE_SESSION_STP_ARMED script={stp_path.name} pid={pid}")

    if spawned:
        device.resume(pid)
        print(f"SINGLE_SESSION_FIFA_RESUMED pid={pid}")

    script_code = SCRIPT
    observe_only = os.environ.get("BLAZE_OBSERVE_ONLY", "").strip().lower() in (
        "1",
        "true",
        "yes",
    )
    if observe_only:
        script_code = script_code.replace("const FORCE_BLAZE = true;", "const FORCE_BLAZE = false;")
        script_code = script_code.replace(
            "const INJECT_BLAZE_ADDR = true;", "const INJECT_BLAZE_ADDR = false;"
        )
        print("BLAZE_OBSERVE_ONLY=1 → FORCE_BLAZE=0 INJECT_BLAZE_ADDR=0")

    script = session.create_script(script_code)
    script.on("message", on_msg)
    try:
        script.load()
    except Exception as e:
        print("script.load failed:", e)
        print("Retrying once…")
        time.sleep(1)
        script = session.create_script(script_code)
        script.on("message", on_msg)
        script.load()

    xref_script = None
    try:
        defer_xref_ms = int(os.environ.get("PIPE_DEFER_XREF_LOAD_MS", "0").strip() or "0")
    except ValueError:
        defer_xref_ms = 0
    defer_xref_ms = max(0, min(defer_xref_ms, 15000))
    resume_gate_text = os.environ.get("PIPE_DEFER_XREF_UNTIL_FILE", "").strip()
    if resume_gate_text:
        resume_gate = Path(resume_gate_text)
        print(
            f"PIPE_DEFER_XREF_UNTIL_FILE={resume_gate} — base network hooks armed; "
            "waiting for confirmed FIFA resume",
            flush=True,
        )
        gate_deadline = time.time() + 45.0
        while not resume_gate.exists() and time.time() < gate_deadline:
            time.sleep(0.05)
        if not resume_gate.exists():
            print("FATAL: FIFA resume gate timeout — xref hooks not loaded", flush=True)
            return 1
        print(
            f"FIFA_RESUME_GATE_OPEN pid={resume_gate.read_text(encoding='ascii').strip()} "
            f"settleMs={defer_xref_ms}",
            flush=True,
        )
        if defer_xref_ms:
            time.sleep(defer_xref_ms / 1000.0)
    elif defer_xref_ms:
        print(
            f"PIPE_DEFER_XREF_LOAD_MS={defer_xref_ms} — base network hooks armed; "
            "waiting for FIFA code initialization",
            flush=True,
        )
        time.sleep(defer_xref_ms / 1000.0)
    if os.environ.get("HOOK_XREFS", "").strip() in ("1", "true", "yes"):
        xref_path = HERE / "frida-hook-offline-xrefs.js"
        fill = os.environ.get("PIPE_FILL_SI", "0").strip()
        do_fill = "true" if fill in ("1", "true", "yes") else "false"
        force = os.environ.get("PIPE_FORCE_ADDR", "1").strip()
        do_force = "true" if force not in ("0", "false", "no") else "false"
        seed = os.environ.get("PIPE_SEED_HOST", "1").strip()
        do_seed = "true" if seed not in ("0", "false", "no") else "false"
        # FILL_LIST fake vtable crashed FIFA — default OFF always unless explicit 1
        flist = os.environ.get("PIPE_FILL_LIST", "0").strip()
        do_flist = "true" if flist in ("1", "true", "yes") else "false"
        force_secure = os.environ.get("PIPE_FORCE_SECURE", "1").strip()
        do_force_secure = "1" if force_secure not in ("0", "false", "no") else "0"
        force_host = os.environ.get("PIPE_FORCE_HOST", "127.0.0.1").strip() or "127.0.0.1"
        # FIX_TIMER: init Fire2+0x270 baseline (default ON with FORCE_ADDR path)
        fix_timer = os.environ.get("PIPE_FIX_TIMER", "1").strip()
        do_fix_timer = "true" if fix_timer not in ("0", "false", "no") else "false"
        ping_obs = os.environ.get("PIPE_PING_OBS", "0").strip()
        do_ping_obs = "true" if ping_obs in ("1", "true", "yes") else "false"
        crash_obs = os.environ.get("PIPE_CRASH_OBS", "1").strip()
        do_crash_obs = "true" if crash_obs not in ("0", "false", "no") else "false"
        crash_fix = os.environ.get("PIPE_CRASH_FIX", "0").strip()
        do_crash_fix = "true" if crash_fix in ("1", "true", "yes") else "false"
        resolver_clean_fix = os.environ.get(
            "PIPE_RESOLVER_CLEAN_FIX", "0"
        ).strip()
        do_resolver_clean_fix = (
            "true"
            if resolver_clean_fix in ("1", "true", "yes")
            else "false"
        )
        origin_online_fix = os.environ.get(
            "PIPE_ORIGIN_ONLINE_FIX", "0"
        ).strip()
        do_origin_online_fix = (
            "true"
            if origin_online_fix in ("1", "true", "yes")
            else "false"
        )
        origin_authcode_fix = os.environ.get(
            "PIPE_ORIGIN_AUTHCODE_FIX", "0"
        ).strip()
        do_origin_authcode_fix = (
            "true"
            if origin_authcode_fix in ("1", "true", "yes")
            else "false"
        )
        origin_version_fix = os.environ.get(
            "PIPE_ORIGIN_VERSION_FIX", "0"
        ).strip()
        do_origin_version_fix = (
            "true"
            if origin_version_fix in ("1", "true", "yes")
            else "false"
        )
        ebisu_fix = os.environ.get("PIPE_EBISU_FIX", "0").strip()
        do_ebisu_fix = (
            "true" if ebisu_fix in ("1", "true", "yes") else "false"
        )
        status_slot_poke = os.environ.get("PIPE_STATUS_SLOT_POKE", "0").strip()
        do_status_slot_poke = (
            "true"
            if status_slot_poke in ("1", "true", "yes")
            else "false"
        )
        status_complete_poke = os.environ.get(
            "PIPE_STATUS_COMPLETE_POKE", "0"
        ).strip()
        do_status_complete_poke = (
            "true"
            if status_complete_poke in ("1", "true", "yes")
            else "false"
        )
        try:
            status_complete_idx_int = int(
                os.environ.get("PIPE_STATUS_COMPLETE_IDX", "1").strip(), 0
            )
        except ValueError:
            status_complete_idx_int = 1
        if status_complete_idx_int < 0 or status_complete_idx_int > 7:
            status_complete_idx_int = 1
        status_complete_idx = str(status_complete_idx_int)
        status_slot0_complete_poke = os.environ.get(
            "PIPE_STATUS_SLOT0_COMPLETE_POKE", "0"
        ).strip()
        do_status_slot0_complete_poke = (
            "true"
            if status_slot0_complete_poke in ("1", "true", "yes")
            else "false"
        )
        cnns_ready_poke = os.environ.get("PIPE_CNNS_READY_POKE", "0").strip()
        do_cnns_ready_poke = (
            "true"
            if cnns_ready_poke in ("1", "true", "yes")
            else "false"
        )
        login_state_poke = os.environ.get("PIPE_LOGIN_STATE_POKE", "0").strip()
        do_login_state_poke = (
            "true"
            if login_state_poke in ("1", "true", "yes")
            else "false"
        )
        login_state_succ_poke = os.environ.get(
            "PIPE_LOGIN_STATE_SUCC_POKE", "0"
        ).strip()
        do_login_state_succ_poke = (
            "true"
            if login_state_succ_poke in ("1", "true", "yes")
            else "false"
        )
        login_complete_call = os.environ.get(
            "PIPE_LOGIN_COMPLETE_CALL", "0"
        ).strip()
        do_login_complete_call = (
            "true"
            if login_complete_call in ("1", "true", "yes")
            else "false"
        )
        login_ret_done_poke = os.environ.get(
            "PIPE_LOGIN_RET_DONE_POKE", "0"
        ).strip()
        do_login_ret_done_poke = (
            "true"
            if login_ret_done_poke in ("1", "true", "yes")
            else "false"
        )
        try:
            login_ret_done_value_int = int(
                os.environ.get("PIPE_LOGIN_RET_DONE_VALUE", "3").strip(), 0
            )
        except ValueError:
            login_ret_done_value_int = 3
        if login_ret_done_value_int < 0 or login_ret_done_value_int > 0xFF:
            login_ret_done_value_int = 3
        login_ret_done_value = str(login_ret_done_value_int)
        auto_detach_after_login = os.environ.get(
            "PIPE_AUTO_DETACH_AFTER_LOGIN", "0"
        ).strip()
        do_auto_detach_after_login = (
            "true"
            if auto_detach_after_login in ("1", "true", "yes")
            else "false"
        )
        auth_waiter_done_poke = os.environ.get(
            "PIPE_AUTH_WAITER_DONE_POKE", "0"
        ).strip()
        do_auth_waiter_done_poke = (
            "true"
            if auth_waiter_done_poke in ("1", "true", "yes")
            else "false"
        )
        auth_jobq_done_poke = os.environ.get(
            "PIPE_AUTH_JOBQ_DONE_POKE", "0"
        ).strip()
        do_auth_jobq_done_poke = (
            "true"
            if auth_jobq_done_poke in ("1", "true", "yes")
            else "false"
        )
        login_260_mam = os.environ.get("PIPE_LOGIN_260_MAM", "0").strip()
        do_login_260_mam = (
            "true" if login_260_mam in ("1", "true", "yes") else "false"
        )
        ext_dispatch = os.environ.get("PIPE_EXT_DISPATCH", "0").strip()
        do_ext_dispatch = (
            "true" if ext_dispatch in ("1", "true", "yes") else "false"
        )
        orphan_listener = os.environ.get("PIPE_ORPHAN_LISTENER", "1").strip()
        do_orphan_listener = (
            "true" if orphan_listener in ("1", "true", "yes") else "false"
        )
        orphan_static_only = os.environ.get("PIPE_ORPHAN_STATIC_ONLY", "0").strip()
        do_orphan_static_only = (
            "true" if orphan_static_only in ("1", "true", "yes") else "false"
        )
        orphan_fn_only = os.environ.get("PIPE_ORPHAN_FN_ONLY", "0").strip()
        do_orphan_fn_only = (
            "true" if orphan_fn_only in ("1", "true", "yes") else "false"
        )
        fail16 = os.environ.get("PIPE_FAIL16", "0").strip()
        do_fail16 = "true" if fail16 in ("1", "true", "yes") else "false"
        auth10_complete = os.environ.get("PIPE_AUTH10_COMPLETE", "0").strip()
        do_auth10_complete = (
            "true" if auth10_complete in ("1", "true", "yes") else "false"
        )
        job_bridge = os.environ.get("PIPE_JOB_BRIDGE", "0").strip()
        do_job_bridge = (
            "true" if job_bridge in ("1", "true", "yes") else "false"
        )
        job_bridge_mam = os.environ.get("PIPE_JOB_BRIDGE_MAM", "0").strip()
        do_job_bridge_mam = (
            "true" if job_bridge_mam in ("1", "true", "yes") else "false"
        )
        waiter_60 = os.environ.get("PIPE_WAITER_60", "0").strip()
        do_waiter_60 = (
            "true" if waiter_60 in ("1", "true", "yes") else "false"
        )
        waiter_slot5_ret_poke = os.environ.get(
            "PIPE_WAITER_SLOT5_RET_POKE", "0"
        ).strip()
        do_waiter_slot5_ret_poke = (
            "true"
            if waiter_slot5_ret_poke in ("1", "true", "yes")
            else "false"
        )
        login_ret6_obs = os.environ.get("PIPE_LOGIN_RET6_OBS", "0").strip()
        do_login_ret6_obs = (
            "true" if login_ret6_obs in ("1", "true", "yes") else "false"
        )
        scheduler_obs = os.environ.get("PIPE_SCHEDULER_OBS", "0").strip()
        do_scheduler_obs = (
            "true" if scheduler_obs in ("1", "true", "yes") else "false"
        )
        scheduler_gate_poke = os.environ.get("PIPE_SCHEDULER_GATE_POKE", "0").strip()
        do_scheduler_gate_poke = (
            "true" if scheduler_gate_poke in ("1", "true", "yes") else "false"
        )
        login_outflags_obs = os.environ.get(
            "PIPE_LOGIN_OUTFLAGS_OBS", "0"
        ).strip()
        do_login_outflags_obs = (
            "true" if login_outflags_obs in ("1", "true", "yes") else "false"
        )
        login_outflags_poke = os.environ.get(
            "PIPE_LOGIN_OUTFLAGS_POKE", "0"
        ).strip()
        do_login_outflags_poke = (
            "true" if login_outflags_poke in ("1", "true", "yes") else "false"
        )
        login_rsi_outflags = os.environ.get(
            "PIPE_LOGIN_RSI_OUTFLAGS", "0"
        ).strip()
        do_login_rsi_outflags = (
            "true" if login_rsi_outflags in ("1", "true", "yes") else "false"
        )
        sdb_ui = os.environ.get("PIPE_SDB_UI", "0").strip()
        do_sdb_ui = "true" if sdb_ui in ("1", "true", "yes") else "false"
        ondemand_success_fix = os.environ.get("PIPE_ONDEMAND_SUCCESS_FIX", "0").strip()
        do_ondemand_success_fix = (
            "true" if ondemand_success_fix in ("1", "true", "yes") else "false"
        )
        xref_code = (
            xref_path.read_text(encoding="utf-8")
            .replace("__FILL_SI__", do_fill)
            .replace("__FORCE_ADDR__", do_force)
            .replace("__SEED_HOST__", do_seed)
            .replace("__FILL_LIST__", do_flist)
            .replace("__FORCE_SECURE__", do_force_secure)
            .replace("__FIX_TIMER__", do_fix_timer)
            .replace("__PING_OBS__", do_ping_obs)
            .replace("__CRASH_OBS__", do_crash_obs)
            .replace("__CRASH_FIX__", do_crash_fix)
            .replace("__RESOLVER_CLEAN_FIX__", do_resolver_clean_fix)
            .replace("__ORIGIN_ONLINE_FIX__", do_origin_online_fix)
            .replace("__ORIGIN_AUTHCODE_FIX__", do_origin_authcode_fix)
            .replace("__ORIGIN_VERSION_FIX__", do_origin_version_fix)
            .replace("__EBISU_FIX__", do_ebisu_fix)
            .replace("__STATUS_SLOT_POKE__", do_status_slot_poke)
            .replace("__STATUS_COMPLETE_POKE__", do_status_complete_poke)
            .replace("__STATUS_COMPLETE_IDX__", status_complete_idx)
            .replace(
                "__STATUS_SLOT0_COMPLETE_POKE__",
                do_status_slot0_complete_poke,
            )
            .replace("__CNNS_READY_POKE__", do_cnns_ready_poke)
            .replace("__LOGIN_STATE_POKE__", do_login_state_poke)
            .replace("__LOGIN_STATE_SUCC_POKE__", do_login_state_succ_poke)
            .replace("__LOGIN_COMPLETE_CALL__", do_login_complete_call)
            .replace("__LOGIN_RET_DONE_POKE__", do_login_ret_done_poke)
            .replace("__LOGIN_RET_DONE_VALUE__", login_ret_done_value)
            .replace("__AUTO_DETACH_AFTER_LOGIN__", do_auto_detach_after_login)
            .replace("__AUTH_WAITER_DONE_POKE__", do_auth_waiter_done_poke)
            .replace("__AUTH_JOBQ_DONE_POKE__", do_auth_jobq_done_poke)
            .replace("__LOGIN_260_MAM__", do_login_260_mam)
            .replace("__EXT_DISPATCH__", do_ext_dispatch)
            .replace("__ORPHAN_LISTENER__", do_orphan_listener)
            .replace("__ORPHAN_STATIC_ONLY__", do_orphan_static_only)
            .replace("__ORPHAN_FN_ONLY__", do_orphan_fn_only)
            .replace("__FAIL16__", do_fail16)
            .replace("__AUTH10_COMPLETE__", do_auth10_complete)
            .replace("__JOB_BRIDGE__", do_job_bridge)
            .replace("__JOB_BRIDGE_MAM__", do_job_bridge_mam)
            .replace("__WAITER_60__", do_waiter_60)
            .replace("__WAITER_SLOT5_RET_POKE__", do_waiter_slot5_ret_poke)
            .replace("__LOGIN_RET6_OBS__", do_login_ret6_obs)
            .replace("__SCHEDULER_OBS__", do_scheduler_obs)
            .replace("__SCHEDULER_GATE_POKE__", do_scheduler_gate_poke)
            .replace("__LOGIN_OUTFLAGS_OBS__", do_login_outflags_obs)
            .replace("__LOGIN_OUTFLAGS_POKE__", do_login_outflags_poke)
            .replace("__LOGIN_RSI_OUTFLAGS__", do_login_rsi_outflags)
            .replace("__SDB_UI__", do_sdb_ui)
            .replace("__ONDEMAND_SUCCESS_FIX__", do_ondemand_success_fix)
            .replace("__FORCE_HOST__", force_host)
        )
        # Sanity: unresolved tokens must never reach Frida (silent CAS B)
        for token in (
            "__FILL_SI__",
            "__FORCE_ADDR__",
            "__SEED_HOST__",
            "__FILL_LIST__",
            "__FORCE_SECURE__",
            "__FIX_TIMER__",
            "__PING_OBS__",
            "__CRASH_OBS__",
            "__CRASH_FIX__",
            "__RESOLVER_CLEAN_FIX__",
            "__ORIGIN_ONLINE_FIX__",
            "__ORIGIN_AUTHCODE_FIX__",
            "__ORIGIN_VERSION_FIX__",
            "__EBISU_FIX__",
            "__STATUS_SLOT_POKE__",
            "__STATUS_COMPLETE_POKE__",
            "__STATUS_COMPLETE_IDX__",
            "__STATUS_SLOT0_COMPLETE_POKE__",
            "__CNNS_READY_POKE__",
            "__LOGIN_STATE_POKE__",
            "__LOGIN_STATE_SUCC_POKE__",
            "__LOGIN_COMPLETE_CALL__",
            "__LOGIN_RET_DONE_POKE__",
            "__LOGIN_RET_DONE_VALUE__",
            "__AUTO_DETACH_AFTER_LOGIN__",
            "__AUTH_WAITER_DONE_POKE__",
            "__AUTH_JOBQ_DONE_POKE__",
            "__LOGIN_260_MAM__",
            "__EXT_DISPATCH__",
            "__ORPHAN_LISTENER__",
            "__ORPHAN_STATIC_ONLY__",
            "__ORPHAN_FN_ONLY__",
            "__FAIL16__",
            "__AUTH10_COMPLETE__",
            "__JOB_BRIDGE__",
            "__JOB_BRIDGE_MAM__",
            "__WAITER_60__",
            "__WAITER_SLOT5_RET_POKE__",
            "__LOGIN_RET6_OBS__",
            "__SCHEDULER_OBS__",
            "__SCHEDULER_GATE_POKE__",
            "__LOGIN_OUTFLAGS_OBS__",
            "__LOGIN_OUTFLAGS_POKE__",
            "__LOGIN_RSI_OUTFLAGS__",
            "__SDB_UI__",
            "__ONDEMAND_SUCCESS_FIX__",
            "__FORCE_HOST__",
        ):
            if token in xref_code:
                print(f"FATAL: unresolved pipe token {token} — aborting xref load")
                return 1
        xref_script = session.create_script(xref_code)
        xref_script.on("message", on_msg)
        try:
            xref_script.load()
        except Exception as e:
            print("FATAL: xref script.load failed:", e)
            return 1
        print(
            f"HOOK_XREFS=1 PIPE_FILL_SI={do_fill} PIPE_SEED_HOST={do_seed} "
            f"PIPE_FILL_LIST={do_flist} PIPE_FORCE_SECURE={do_force_secure} "
            f"PIPE_FORCE_HOST={force_host} PIPE_FORCE_ADDR={do_force} "
            f"PIPE_FIX_TIMER={do_fix_timer} PIPE_PING_OBS={do_ping_obs} "
            f"PIPE_CRASH_OBS={do_crash_obs} "
            f"PIPE_CRASH_FIX={do_crash_fix} "
            f"PIPE_RESOLVER_CLEAN_FIX={do_resolver_clean_fix} "
            f"PIPE_ORIGIN_ONLINE_FIX={do_origin_online_fix} "
            f"PIPE_ORIGIN_AUTHCODE_FIX={do_origin_authcode_fix} "
            f"PIPE_ORIGIN_VERSION_FIX={do_origin_version_fix} "
            f"PIPE_EBISU_FIX={do_ebisu_fix} "
            f"PIPE_STATUS_SLOT_POKE={do_status_slot_poke} "
            f"PIPE_STATUS_COMPLETE_POKE={do_status_complete_poke} "
            f"PIPE_STATUS_COMPLETE_IDX={status_complete_idx} "
            f"PIPE_STATUS_SLOT0_COMPLETE_POKE={do_status_slot0_complete_poke} "
            f"PIPE_CNNS_READY_POKE={do_cnns_ready_poke} "
            f"PIPE_LOGIN_STATE_POKE={do_login_state_poke} "
            f"PIPE_LOGIN_STATE_SUCC_POKE={do_login_state_succ_poke} "
            f"PIPE_LOGIN_COMPLETE_CALL={do_login_complete_call} "
            f"PIPE_LOGIN_RET_DONE_POKE={do_login_ret_done_poke} "
            f"PIPE_LOGIN_RET_DONE_VALUE={login_ret_done_value} "
            f"PIPE_AUTO_DETACH_AFTER_LOGIN={do_auto_detach_after_login} "
            f"PIPE_AUTH_WAITER_DONE_POKE={do_auth_waiter_done_poke} "
            f"PIPE_AUTH_JOBQ_DONE_POKE={do_auth_jobq_done_poke} "
            f"PIPE_LOGIN_260_MAM={do_login_260_mam} "
            f"PIPE_EXT_DISPATCH={do_ext_dispatch} "
            f"PIPE_ORPHAN_LISTENER={do_orphan_listener} "
            f"PIPE_ORPHAN_STATIC_ONLY={do_orphan_static_only} "
            f"PIPE_ORPHAN_FN_ONLY={do_orphan_fn_only} "
            f"PIPE_FAIL16={do_fail16} "
            f"PIPE_AUTH10_COMPLETE={do_auth10_complete} "
            f"PIPE_JOB_BRIDGE={do_job_bridge} "
            f"PIPE_JOB_BRIDGE_MAM={do_job_bridge_mam} "
            f"PIPE_WAITER_60={do_waiter_60} "
            f"PIPE_WAITER_SLOT5_RET_POKE={do_waiter_slot5_ret_poke} "
            f"PIPE_LOGIN_RET6_OBS={do_login_ret6_obs} "
            f"PIPE_SCHEDULER_OBS={do_scheduler_obs} "
            f"PIPE_SCHEDULER_GATE_POKE={do_scheduler_gate_poke} "
            f"PIPE_LOGIN_OUTFLAGS_OBS={do_login_outflags_obs} "
            f"PIPE_LOGIN_OUTFLAGS_POKE={do_login_outflags_poke} "
            f"PIPE_LOGIN_RSI_OUTFLAGS={do_login_rsi_outflags} "
            f"PIPE_SDB_UI={do_sdb_ui} "
            f"PIPE_ONDEMAND_SUCCESS_FIX={do_ondemand_success_fix} "
            "INNER_JOBQ_REV=4 — pipeline hooks loaded"
        )

    census_script = None
    if os.environ.get("PIPE_CENSUS_TDF_DUMP", "").strip() in ("1", "true", "yes"):
        census_path = HERE / "frida-dump-census-tdf.js"
        census_script = session.create_script(census_path.read_text(encoding="utf-8"))
        census_script.on("message", on_msg)
        try:
            census_script.load()
        except Exception as e:
            print("FATAL: census TDF script.load failed:", e)
            return 1
        print("PIPE_CENSUS_TDF_DUMP=1 — Census TDF metadata dump armed")

    print("Bypass chargé (v113 + optional xref hooks).")
    print("Ordre: npm start → FIFA → bypass → UT")
    print("Cherche: ★★★ BLAZE_CONNECT ; avec HOOK_XREFS: lignes [xref]")
    print("Copie les lignes ★ / [xref] ici. NE PAS Ctrl+C trop tôt.")

    print(f"Log auto: {log_path}")
    print("NE PAS Ctrl+C tant que le test UT n'est pas fini.")
    try:
        # Always park here — stdin.read() returns immediately under PowerShell/agent
        # and would detach Frida before UT. Ctrl+C to stop.
        while True:
            if auto_detach_requested["value"]:
                print(
                    "\n=== AUTO_DETACH_AFTER_LOGIN — unloading Frida session "
                    f"reason={auto_detach_requested['reason']} ==="
                )
                try:
                    script.unload()
                except Exception as e:
                    print(f"script.unload failed: {e}")
                try:
                    session.detach()
                except Exception as e:
                    print(f"session.detach failed: {e}")
                break
            time.sleep(0.25)
    except KeyboardInterrupt:
        print("\n=== KeyboardInterrupt — fin session ===")
    finally:
        print(f"=== log sauvé: {log_path} ===")
        try:
            log_f.close()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
