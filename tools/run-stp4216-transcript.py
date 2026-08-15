#!/usr/bin/env python3
"""
STP4216 transcript + PROTOCOL_AUDIT runner.
Captures NUL-framed LSX on :4216, dual-decrypts (session + default 00..0f),
validates Request/Response/Event contracts, emits STP4216_* tags.
No FIFA pokes. No STP reply injection.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path
from xml.etree import ElementTree as ET

import frida

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from lsx_crypto import LsxSessionTracker  # noqa: E402

SCRIPT_PATH = Path(
    os.environ.get("STP_FRIDA_SCRIPT", "").strip()
    or str(HERE / "frida-stp4216-transcript.js")
)
SSL_PATH = HERE / "frida-ssl-bypass.js"
REDIR_COMMIT_PATH = HERE / "frida-redir-commit-obs.js"
ORIGIN_VERSION_PATH = HERE / "frida-origin-version-fix.js"
ORIGIN_VERSION_PATH_OBS = HERE / "frida-origin-version-path-obs.js"
ORIGIN_JOB_PAYLOAD_OBS = HERE / "frida-origin-job-payload-obs.js"
ORIGIN_JOB_DISPATCH_OBS = HERE / "frida-origin-job-dispatch-obs.js"
LOG_DIR = HERE / "versions" / "stp4216-transcript"


def find_fifa_pid() -> int:
    wait_for_fifa = os.environ.get("STP_WAIT_FOR_FIFA", "0").strip() in (
        "1",
        "true",
        "True",
        "yes",
    )
    deadline = time.time() + 60.0
    while True:
        for p in frida.get_local_device().enumerate_processes():
            if p.name.lower() in ("fifa17.exe", "fifa17"):
                return int(p.pid)
        if not wait_for_fifa or time.time() >= deadline:
            raise SystemExit("FIFA17.exe not running")
        time.sleep(0.02)


def default_fifa_path() -> Path:
    env = os.environ.get("FIFA17_EXE", "").strip()
    if env:
        return Path(env)
    cand = ROOT.parent / "FIFA 17" / "FIFA17.exe"
    if cand.is_file():
        return cand
    raise SystemExit("set FIFA17_EXE=")


PROFILE_FIELDS = (
    "UserIndex",
    "UserId",
    "PersonaId",
    "Persona",
    "AvatarId",
    "Country",
    "IsUnderAge",
    "IsSubscriber",
    "IsTrialSubscriber",
    "SubscriberLevel",
    "GeoCountry",
    "CommerceCountry",
    "CommerceCurrency",
    "IsSteamSubscriber",
)

PRESENCE_FIELDS = (
    "UserId",
    "Presence",
    "Title",
    "TitleId",
    "MultiplayerId",
    "RichPresence",
    "GamePresence",
    "SessionId",
    "Group",
    "GroupId",
)


def body_type(xml: str) -> str:
    patterns = [
        r"<(GetConfigResponse|GetConfig|GetSettingsResponse|GetSettings|GetSettingResponse|"
        r"GetSetting|GetInternetConnectedState|InternetConnectedState|"
        r"GetProfileResponse|GetProfile|GetAuthCode|AuthCode|GetAuthToken|AuthToken|"
        r"PostWincodes|MiddlewareConnectResult|"
        r"GetPresence|GoOnline|ErrorSuccess|Login|LoginEvent|LOGIN_EVENT|"
        r"OnlineStatusEvent|ONLINE_STATUS_EVENT|CurrentUserPresenceEvent|ProfileEvent|"
        r"QueryEntitlements|ChallengeAccepted|ChallengeResponse|Challenge)\b",
    ]
    for pat in patterns:
        m = re.search(pat, xml, re.I)
        if m:
            return m.group(1)
    m = re.search(r"<([A-Za-z][A-Za-z0-9_]+)\b", xml[5:] if xml.startswith("<LSX>") else xml)
    return m.group(1) if m else "?"


def attr(xml: str, name: str) -> str:
    m = re.search(rf'\b{name}="([^"]*)"', xml, re.I)
    return m.group(1) if m else ""


def parse_facilities(xml: str) -> list[tuple[str, str]]:
    """Facility/Service → recipient. Supports Facility and Service@Name/@Facility shapes."""
    out: list[tuple[str, str]] = []
    # origin-sdk: <Service Name="EbisuSDK" Facility="LOGIN_EVENT"/>
    for m in re.finditer(
        r'<Service\b[^>]*\bName="([^"]+)"[^>]*\bFacility="([^"]+)"',
        xml,
        re.I,
    ):
        out.append((m.group(2), m.group(1)))  # facility → service name
    for m in re.finditer(
        r'<Service\b[^>]*\bFacility="([^"]+)"[^>]*\bName="([^"]+)"',
        xml,
        re.I,
    ):
        out.append((m.group(1), m.group(2)))
    for m in re.finditer(
        r'<Facility\b[^>]*\b(?:name|Name)="([^"]+)"[^>]*\b(?:recipient|Recipient)="([^"]+)"',
        xml,
        re.I,
    ):
        out.append((m.group(1), m.group(2)))
    for m in re.finditer(
        r'<Facility\b[^>]*\b(?:recipient|Recipient)="([^"]+)"[^>]*\b(?:name|Name)="([^"]+)"',
        xml,
        re.I,
    ):
        out.append((m.group(2), m.group(1)))
    for m in re.finditer(
        r"<Facility\b[^>]*>\s*<Name>([^<]+)</Name>\s*<Recipient>([^<]+)</Recipient>",
        xml,
        re.I | re.S,
    ):
        out.append((m.group(1).strip(), m.group(2).strip()))
    if not out:
        for m in re.finditer(
            r"(SDK|PROFILE|LOGIN_EVENT|LOGIN|ONLINE_STATUS_EVENT|ONLINE_STATUS|"
            r"PROFILE_EVENT|PRESENCE_EVENT|UTILITY|PRESENCE|CHAT_EVENT|PERMISSION|CONTENT|EALS_EVENTS)"
            r'[^A-Za-z0-9_]{1,40}(EbisuSDK|EALS|Utility|XMPP|Origin)',
            xml,
            re.I,
        ):
            out.append((m.group(1), m.group(2)))
    seen = set()
    uniq = []
    for a, b in out:
        k = (a.upper(), b)
        if k not in seen:
            seen.add(k)
            uniq.append((a, b))
    return uniq


class TranscriptSink:
    def __init__(self, log_path: Path, latest: Path) -> None:
        self.log_path = log_path
        self.latest = latest
        self.lines: list[str] = []
        self.tracker = LsxSessionTracker()
        self.messages: list[str] = []
        self.decrypt_ok = 0
        self.decrypt_fail = 0
        self.session_key_logged = False
        self.facilities: dict[str, str] = {}
        self.challenge_meta: dict[str, str] = {}
        self.saw_login_event = False
        self.saw_online_event = False
        self.login_event_sender: str | None = None
        self.login_event_fields: dict[str, str] = {}
        self.online_connected: str | None = None
        self.origin_check_rets: list[str] = []
        self.login_leaves: list[str] = []
        self.login_complete_enter = False
        self.txt_not_login = False
        self.order = 0
        self.launch_env: dict[str, str] = {}
        self.manual_offline: str | None = None
        self.goonline_code: str | None = None
        self.goonline_seen = False
        self.online_event_is_online: str | None = None
        self.sdk_protocol_version: str | None = None
        self.sdk_version: str | None = None
        self.error_success_codes: list[str] = []
        self.decrypt_key_modes: dict[str, int] = {}
        self.pending_requests: dict[str, dict[str, str]] = {}
        self.id_match_ok = 0
        self.id_match_fail = 0
        self.event_with_id = 0
        self.response_without_id = 0
        self.request_without_id = 0
        self.profile_fields: dict[str, str] = {}
        self.presence_fields: dict[str, str] = {}
        self.middleware_reason: str | None = None
        self.postwincodes_seen = False
        self.authcode_value: str | None = None
        self.login_as_response = False  # Login body inside <Response> (wrong envelope)
        self.identity: dict[str, str] = {}  # ContentId/MultiplayerId/UserId/Persona consistency
        self.rewrite_match = 0
        self.rewrite_sent = 0
        self.rewrite_verify_ok = False
        self.origin_check_online_val: str | None = None
        self.config_rewrite_match = 0
        self.config_rewrite_sent = 0
        self.config_rewrite_verify = False
        self.recipients_after_config: list[str] = []
        self.empty_recipient_after_config = 0
        self.nonempty_recipient_after_config = 0
        self.saw_config_true = False
        self.blaze_connect_seen = False
        self.blaze_cas: str | None = None
        self.redir_commit_verdict: str | None = None
        self.resolve_cb_seen = False
        self.force_addr_applied = False
        self.force_addr_verified = False
        self.force_addr_causal_verdict: str | None = None
        self.handshake_captured = False
        self.challenge_accepted_seen = False
        self.session_key_seen = False
        self.connected_rewrite_sent = False
        self.connected_rewrite_verify = False
        self.goonline_tag_seen = False
        self.online_event_tag_seen = False
        self.login_event_tag_seen = False
        self.blaze_auth10_seen = False
        self.lsx_restore_verdict: str | None = None
        self.origin_online_fix_applied = 0
        self.origin_online_fix_ret_was: str | None = None
        self.origin_version_gate_hits = 0
        self.origin_version_fix_applied = 0
        self.origin_auth_setup_eax: str | None = None
        self.authsetup_enter = 0
        self.authsetup_leave = 0
        self.authsetup_leave_ret: str | None = None
        self.auth_callsite_717d68d_hits = 0
        self.origin_check_enter = 0
        self.origin_check_leave_obs = 0
        self.origin_check_tid: str | None = None
        self.stalker_origin_start = 0
        self.ui_handoff_msg = 0
        self.ui_handoff_async = 0
        self.ui_handoff_sync = 0
        self.ui_stalker_start = 0
        self.fifa_window_tid: str | None = None
        self.async_callback_enter = 0
        self.job_enqueue = 0
        self.job_wake = 0
        self.job_indirect = 0
        self.job_indirect_target: str | None = None
        self.job_payload_match = 0
        self.job_seq1_enqueue = 0
        self.job_seq1_wake = 0
        self.job_dispatch_enter = 0
        self.job_callback_dispatch = 0
        self.job_callback_enter = 0
        self.job_callback_rcx_match = 0
        self.job_callback_wake_tid_match = 0
        self.job_callback_target: str | None = None
        self.callback_sync = 0
        self.callback_ui = 0
        self.callback_async = 0
        self.callback_global_write = 0
        self.job_ctx_match = 0
        self.seq1_control_transfer = 0
        self.seq1_target_enter = 0
        self.seq1_target_with_node = 0
        self.seq1_tailcall_with_node = 0
        self.seq1_identified_target: str | None = None
        self.seq1_sync = 0
        self.seq1_ui = 0
        self.seq1_async = 0
        self.seq1_global_write = 0
        self.seq1_node_capture = 0
        self.seq1_vmethod_hooked = 0
        self.seq1_vmethod_enter = 0
        self.seq1_vmethod_rcx_match = 0
        self.seq1_vmethod_generic = 0
        self.seq1_vmethod_leave = 0
        self.seq1_payload_target_enter = 0
        self.seq1_callback_sync = 0
        self.seq1_callback_ui = 0
        self.seq1_callback_async = 0
        self.seq1_vmethod_target: str | None = None
        self.origin_epoch_active = 0
        self.origin_job_node_candidate = 0
        self.origin_job_vmethod_enter = 0
        self.origin_job_vmethod_leave = 0
        self.origin_job_target_identified = 0
        self.origin_callback_sync = 0
        self.origin_callback_ui = 0
        self.origin_callback_async = 0
        self.origin_job_payload_enter = 0
        self.boot_job_skipped = 0
        self.job_vmethod_dispatch_confirmed = 0
        self.origin_identified_target: str | None = None
        self.origin_epoch_notify = None
        self.origin_secondary_handle = 0
        self.origin_second_wait_enter = 0
        self.origin_second_wait_wake = 0
        self.origin_second_sync_identified = 0
        self.second_stage_target_enter = 0
        self.second_stage_ui = 0
        self.second_stage_sync = 0
        self.second_stage_async = 0
        self.second_stage_lsx = 0
        self.second_stage_reentry = 0
        self.second_stage_dispatch_enter = 0
        self.second_sync_handoff_confirmed = 0
        self.second_stage_job_candidate = 0
        self.second_stage_control_transfer = 0
        self.second_stage_oneshot_armed = 0
        self.second_reentry_hook_miss = 0
        self.second_stage_vmethod_dispatch = 0
        self.second_stage_indirect_call = 0
        # LSX_PROFILE8_SETPRESENCE_ORDER_RACE
        self.lsx_timeline = 0
        self.profile8_barrier_armed = 0
        self.profile8_response_held = 0
        self.setpresence9_seen = 0
        self.profile8_response_released = 0
        self.profile8_barrier_timeout = 0
        self.profile8_hash_dup = 0
        self.profile8_unique_req = 0
        self.get_internet_connected_seen = 0
        self.profile8_fifa_order: list[str] = []
        self.profile8_order_by_sock: dict[str, list[str]] = {}
        self.profile8_request_count = 0
        self.profile8_response_order: list[str] = []
        self.profile8_last_request_id: str = "-"
        self.lsx_id_bodytype_mismatch = 0
        self.arm_obs_skipped = 0
        self.arm_profile8_passive = 0
        # :4216 handshake stage axis (pre-SESSION_KEY)
        self.hs_dll_loaded = 0
        self.hs_bind_4216 = 0
        self.hs_listen_4216 = 0
        self.hs_client_connect = 0
        self.hs_accept = 0
        self.hs_challenge = 0
        self.hs_challenge_response = 0
        self.hs_challenge_accepted = 0
        self.hs_session_key = 0
        self.hs_socket_closed = 0
        self.hs_close_side = "-"
        self.hs_last_wsa_error = -1
        self.hs_last_stage = "init"
        self.hs_summary_line: str | None = None
        self.arm_profile8 = 0
        self.arm_origin_bridge = 0
        self.arm_obs_v11 = 0
        self.origin_payload_enter = 0
        self.origin_callback_sync_secondary = 0
        self.origin_pool_handle_seen = 0
        self.version_text_found = 0
        self.version_text_reads = 0
        self.version_text_writes = 0
        self.version_scan_credible = 0
        self.version_error_imm = 0
        self.version_error_ret = 0
        self.version_token_xref_hits = 0
        self.localize_token_seen = False
        self.popup_dispatch_seen = False
        self.get_authcode_seen = False
        self._arm_obs_callback = None
    def out(self, text: str) -> None:
        print(text)
        self.lines.append(text)
        try:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError:
            pass
        if "STP4216_CALLBACK_CORR" in text or "STP4216_LOGIN_EVENT_CORR" in text:
            if "OriginCheckOnline LEAVE" in text or "OriginCheckOnline ret" in text:
                self.origin_check_rets.append(text)
                self.tag(
                    "STP4216_OUTFLAGS_CORR",
                    "originCheck " + text.split("CORR", 1)[-1].strip(),
                )
            if "LoginStateLogin" in text:
                self.login_leaves.append(text)
                if "TXT_NOT_LOGIN" in text:
                    self.txt_not_login = True
                self.tag(
                    "STP4216_LOGIN_EVENT_CORR",
                    "loginLeave " + text.split("CORR", 1)[-1].strip(),
                )
            if "LoginComplete ENTER" in text or "LoginStateLoginComplete ENTER" in text:
                self.login_complete_enter = True
                self.tag("STP4216_LOGIN_EVENT_CORR", "LoginComplete ENTER ★")
        if "STP4216_LAUNCH_ENV" in text:
            m = re.search(r'key=(\S+)\s+value=(.+)$', text)
            if m:
                self.launch_env[m.group(1)] = m.group(2)
        # Rewrite connected-only observability
        if "STP_REWRITE_MATCH" in text:
            self.rewrite_match += 1
        if "STP_REWRITE_SENT" in text:
            self.rewrite_sent += 1
        if "STP_REWRITE_VERIFY" in text and "connected=1" in text and "ok=1" in text:
            self.rewrite_verify_ok = True
        # LSX_PROFILE8 timeline / barrier — per socket/connection, bodyType is authoritative
        if (
            "LSX_TIMELINE" in text
            and "LSX_TIMELINE_DUP" not in text
            and "LSX_TIMELINE_ERR" not in text
        ):
            self.lsx_timeline += 1
            self.tag("LSX_TIMELINE", text.split("LSX_TIMELINE", 1)[-1].strip()[:360])
            sock_m = re.search(r"\bsocket=(\S+)", text)
            conn_m = re.search(r"\bconnectionId=(\S+)", text)
            sock_key = (
                f"{conn_m.group(1) if conn_m else '-'}|{sock_m.group(1) if sock_m else '-'}"
            )
            if sock_key not in self.profile8_order_by_sock:
                self.profile8_order_by_sock[sock_key] = []
            sock_order = self.profile8_order_by_sock[sock_key]
            id_m = re.search(r"\bid=(\d+)\b", text)
            btype_m = re.search(r"\bbodyType=(\S+)", text)
            btype = btype_m.group(1) if btype_m else "?"
            if id_m and "direction=FIFA_TO_STP" in text:
                self.profile8_last_request_id = id_m.group(1)
            if "direction=FIFA_TO_STP" in text:
                if btype == "GetProfile" and id_m and id_m.group(1) == "8":
                    self.profile8_request_count += 1
                    ord_m = re.search(r"ordinal=(\d+)", text)
                    if ord_m and "uniqueHash=1" in text:
                        self.profile8_unique_req = max(
                            self.profile8_unique_req, int(ord_m.group(1))
                        )
                        label = f"GetProfile#{ord_m.group(1)}"
                        # Global list kept for legacy summary only — not causal proof
                        self.profile8_fifa_order.append(label)
                        sock_order.append(label)
                elif btype == "SetPresence" and id_m and id_m.group(1) == "9":
                    label = "SetPresence#9"
                    if label not in self.profile8_fifa_order:
                        self.profile8_fifa_order.append(label)
                    if label not in sock_order:
                        sock_order.append(label)
                elif id_m:
                    label = f"{btype}#{id_m.group(1)}"
                    if label not in sock_order:
                        sock_order.append(label)
                    if id_m.group(1) == "10" and "Request#10" not in self.profile8_fifa_order:
                        self.profile8_fifa_order.append("Request#10")
                    if re.search(r"\bid=1[1-6]\b", text):
                        glabel = f"Request#{id_m.group(1)}"
                        if glabel not in self.profile8_fifa_order:
                            self.profile8_fifa_order.append(glabel)
            if "direction=STP_TO_FIFA" in text and id_m:
                label = f"{btype}#{id_m.group(1)}"
                if label not in self.profile8_response_order:
                    self.profile8_response_order.append(label)
                if label not in sock_order:
                    sock_order.append(f"RESP:{label}")
        if "LSX_ID_BODYTYPE_MISMATCH" in text:
            self.lsx_id_bodytype_mismatch += 1
            self.tag(
                "LSX_ID_BODYTYPE_MISMATCH",
                text.split("LSX_ID_BODYTYPE_MISMATCH", 1)[-1].strip()[:240],
            )
        if "ARM_PROFILE8_TIMELINE_PASSIVE" in text:
            self.arm_profile8_passive += 1
            self.tag(
                "ARM_PROFILE8_TIMELINE_PASSIVE",
                text.split("ARM_PROFILE8_TIMELINE_PASSIVE", 1)[-1].strip()[:160],
            )
        if "LSX_RESPONSE_TIMING" in text:
            self.tag(
                "LSX_RESPONSE_TIMING",
                text.split("LSX_RESPONSE_TIMING", 1)[-1].strip()[:260],
            )
        if "PROFILE8_BARRIER_ACTIVE" in text:
            self.tag(
                "PROFILE8_BARRIER_ACTIVE",
                text.split("PROFILE8_BARRIER_ACTIVE", 1)[-1].strip()[:200],
            )
        if "PROFILE8_BARRIER_ARMED" in text:
            self.profile8_barrier_armed += 1
            self.tag(
                "PROFILE8_BARRIER_ARMED",
                text.split("PROFILE8_BARRIER_ARMED", 1)[-1].strip()[:200],
            )
        if "PROFILE8_RESPONSE_HELD" in text:
            self.profile8_response_held += 1
            self.tag(
                "PROFILE8_RESPONSE_HELD",
                text.split("PROFILE8_RESPONSE_HELD", 1)[-1].strip()[:220],
            )
        if "SETPRESENCE9_SEEN" in text:
            self.setpresence9_seen += 1
            self.tag(
                "SETPRESENCE9_SEEN",
                text.split("SETPRESENCE9_SEEN", 1)[-1].strip()[:220],
            )
        if "PROFILE8_RESPONSE_RELEASED" in text:
            self.profile8_response_released += 1
            self.tag(
                "PROFILE8_RESPONSE_RELEASED",
                text.split("PROFILE8_RESPONSE_RELEASED", 1)[-1].strip()[:260],
            )
        if "PROFILE8_BARRIER_TIMEOUT" in text:
            self.profile8_barrier_timeout += 1
            self.tag(
                "PROFILE8_BARRIER_TIMEOUT",
                text.split("PROFILE8_BARRIER_TIMEOUT", 1)[-1].strip()[:200],
            )
        if "LSX_PROFILE8_HASH_DUP" in text:
            self.profile8_hash_dup += 1
            self.tag(
                "LSX_PROFILE8_HASH_DUP",
                text.split("LSX_PROFILE8_HASH_DUP", 1)[-1].strip()[:200],
            )
        # :4216 handshake stage markers (pre-SESSION_KEY axis)
        if "LSX_DLL_LOADED" in text:
            self.hs_dll_loaded = 1
            self.hs_last_stage = "dllLoaded"
            self.tag("LSX_DLL_LOADED", text.split("LSX_DLL_LOADED", 1)[-1].strip()[:200])
        if "LSX_BIND_4216" in text:
            self.hs_bind_4216 = 1
            self.hs_last_stage = "bind4216"
            self.tag("LSX_BIND_4216", text.split("LSX_BIND_4216", 1)[-1].strip()[:200])
        if "LSX_LISTEN_4216" in text:
            self.hs_listen_4216 = 1
            self.hs_last_stage = "listen4216"
            self.tag("LSX_LISTEN_4216", text.split("LSX_LISTEN_4216", 1)[-1].strip()[:200])
        if "LSX_CLIENT_CONNECT" in text:
            self.hs_client_connect = 1
            self.hs_last_stage = "clientConnect"
            self.tag(
                "LSX_CLIENT_CONNECT",
                text.split("LSX_CLIENT_CONNECT", 1)[-1].strip()[:200],
            )
        if "LSX_ACCEPT" in text and "note=fail" not in text:
            self.hs_accept = 1
            self.hs_last_stage = "accept"
            self.tag("LSX_ACCEPT", text.split("LSX_ACCEPT", 1)[-1].strip()[:200])
        if "LSX_CHALLENGE_SEEN" in text or "STP4216_CHALLENGE " in text:
            self.hs_challenge = 1
            self.hs_last_stage = "challenge"
            self.tag("LSX_CHALLENGE_SEEN", text.split("CHALLENGE", 1)[-1].strip()[:160])
        if "LSX_CHALLENGE_RESPONSE_SEEN" in text or "STP4216_CHALLENGE_RESPONSE" in text:
            self.hs_challenge_response = 1
            self.hs_last_stage = "challengeResponse"
            self.tag(
                "LSX_CHALLENGE_RESPONSE_SEEN",
                text.split("CHALLENGE_RESPONSE", 1)[-1].strip()[:160],
            )
        if "LSX_CHALLENGE_ACCEPTED_SEEN" in text or "STP4216_CHALLENGE_ACCEPTED" in text:
            self.hs_challenge_accepted = 1
            self.challenge_accepted_seen = True
            self.hs_last_stage = "challengeAccepted"
        if "LSX_SESSION_KEY" in text or "STP4216_SESSION_KEY" in text or "STP_REWRITE_KEY" in text:
            self.hs_session_key = 1
            self.session_key_seen = True
            self.hs_last_stage = "sessionKey"
        if "LSX_SOCKET_CLOSED" in text:
            self.hs_socket_closed = 1
            m_side = re.search(r"\bcloseSide=(\S+)", text)
            if m_side:
                self.hs_close_side = m_side.group(1)
            self.tag(
                "LSX_SOCKET_CLOSED",
                text.split("LSX_SOCKET_CLOSED", 1)[-1].strip()[:220],
            )
        if "LSX_HANDSHAKE_SUMMARY" in text:
            self.hs_summary_line = text.split("LSX_HANDSHAKE_SUMMARY", 1)[-1].strip()[:400]
            m_err = re.search(r"\blastWsaError=(-?\d+)", text)
            if m_err:
                try:
                    self.hs_last_wsa_error = int(m_err.group(1))
                except ValueError:
                    pass
            m_stage = re.search(r"\blastStage=(\S+)", text)
            if m_stage:
                self.hs_last_stage = m_stage.group(1)
            self.tag("LSX_HANDSHAKE_SUMMARY", self.hs_summary_line or "")
        if "ARM_PROFILE8_AXIS" in text:
            self.arm_profile8 += 1
            self.tag("ARM_PROFILE8_AXIS", text.split("ARM_PROFILE8_AXIS", 1)[-1].strip()[:120])
        if "ARM_ORIGIN_BRIDGE" in text:
            self.arm_origin_bridge += 1
            self.tag("ARM_ORIGIN_BRIDGE", text.split("ARM_ORIGIN_BRIDGE", 1)[-1].strip()[:120])
        if "ARM_OBS_V11_SKIPPED" in text:
            self.arm_obs_skipped += 1
            self.tag(
                "ARM_OBS_V11_SKIPPED",
                text.split("ARM_OBS_V11_SKIPPED", 1)[-1].strip()[:120],
            )
        if "ARM_OBS_V11" in text and "ARM_OBS_V11_SKIPPED" not in text:
            self.arm_obs_v11 += 1
            self.tag("ARM_OBS_V11", text.split("ARM_OBS_V11", 1)[-1].strip()[:160])
            if self._arm_obs_callback and self.arm_obs_v11 == 1:
                # Defer load off the Frida message path to avoid reentrant hang.
                cb = self._arm_obs_callback
                try:
                    import threading

                    threading.Timer(0.05, cb).start()
                except Exception as e:
                    self.out(f"[stp4216] ARM_OBS_V11 schedule failed: {e}")
                    try:
                        cb()
                    except Exception as e2:
                        self.out(f"[stp4216] ARM_OBS_V11 load failed: {e2}")
        if "STP_CONFIG_REWRITE_MATCH" in text:
            self.config_rewrite_match += 1
        if "STP_CONFIG_REWRITE_SENT" in text:
            self.config_rewrite_sent += 1
        if "STP_CONFIG_REWRITE_VERIFY" in text and "ok=1" in text:
            self.config_rewrite_verify = True
            self.tag("STP_CONFIG_MAP_ACCEPTED", "verify=ok rewrite sent")
        if "STP_CONNECTED_CORR" in text and "OriginCheckOnline LEAVE" in text:
            m = re.search(r"\bonline=(\S+)", text)
            if m:
                self.origin_check_online_val = m.group(1)
            m2 = re.search(r"\bret=(-?\d+)", text)
            if m2 and self.origin_check_online_val is None:
                self.origin_check_online_val = m2.group(1)
            self.tag(
                "ORIGIN_CHECK_ONLINE_RESULT",
                f"online={self.origin_check_online_val!r} rewriteSent={self.rewrite_sent} "
                f"decryptOk={self.decrypt_ok}",
            )
        if "STP4216_HANDSHAKE_CAPTURED" in text or "STP4216_HANDSHAKE " in text:
            self.handshake_captured = True
        if "STP4216_CHALLENGE_ACCEPTED" in text or (
            "STP4216_HANDSHAKE" in text and "ChallengeAccepted" in text
        ):
            self.challenge_accepted_seen = True
        if "STP4216_SESSION_KEY" in text or "STP_REWRITE_KEY" in text:
            self.session_key_seen = True
        if "STP_CONNECTED_REWRITE_SENT" in text or (
            "STP_REWRITE_SENT" in text and self.rewrite_verify_ok
        ):
            self.connected_rewrite_sent = True
            self.tag("STP_CONNECTED_REWRITE_SENT", "seen=1")
        if "STP_CONNECTED_REWRITE_VERIFY" in text and "ok=1" in text:
            self.connected_rewrite_verify = True
        if "STP4216_GOONLINE" in text or "STP_GOONLINE" in text:
            self.goonline_tag_seen = True
            self.tag("STP_GOONLINE", text.split("GOONLINE", 1)[-1].strip()[:200])
        if "STP4216_ONLINE_EVENT" in text or "STP_ONLINE_EVENT" in text:
            self.online_event_tag_seen = True
            self.tag("STP_ONLINE_EVENT", text.split("ONLINE_EVENT", 1)[-1].strip()[:200])
        if "STP4216_LOGIN_EVENT" in text or "STP_LOGIN_EVENT" in text:
            self.login_event_tag_seen = True
            self.tag("STP_LOGIN_EVENT", text.split("LOGIN_EVENT", 1)[-1].strip()[:200])
        if "ORIGIN_ONLINE_FIX" in text and "applied=1" in text:
            # Ignore echoed lines (ORIGIN_EPOCH_ACTIVE info embeds the fix tag).
            if "ORIGIN_EPOCH" in text or "ORIGIN_JOB_" in text:
                pass
            else:
                self.origin_online_fix_applied += 1
                m = re.search(r"retWas=(0x[0-9a-fA-F]+)", text)
                if m:
                    self.origin_online_fix_ret_was = m.group(1)
                self.tag(
                    "ORIGIN_ONLINE_FIX",
                    text.split("ORIGIN_ONLINE_FIX", 1)[-1].strip()[:200],
                )
                # Post epoch once per real bridge apply
                if self.origin_online_fix_applied == 1 and self.origin_epoch_notify:
                    try:
                        self.origin_epoch_notify(text)
                    except Exception as e:
                        self.out(f"[job] ORIGIN_EPOCH_POST_FAIL {e}")
        if "ORIGIN_ONLINE_FIX_APPLIED" in text and "ORIGIN_EPOCH" not in text:
            # Require real rewrite tag (retWas=), ignore ARMED/banner echoes
            if "retWas=" in text or "retNow=" in text:
                self.tag(
                    "ORIGIN_ONLINE_FIX_APPLIED",
                    text.split("ORIGIN_ONLINE_FIX_APPLIED", 1)[-1].strip()[:200],
                )
        if "ORIGIN_EPOCH_ACTIVE" in text:
            self.origin_epoch_active += 1
            self.tag(
                "ORIGIN_EPOCH_ACTIVE",
                text.split("ORIGIN_EPOCH_ACTIVE", 1)[-1].strip()[:240],
            )
        if "ORIGIN_JOB_NODE_CANDIDATE" in text:
            self.origin_job_node_candidate += 1
            self.seq1_node_capture += 1
            self.tag(
                "ORIGIN_JOB_NODE_CANDIDATE",
                text.split("ORIGIN_JOB_NODE_CANDIDATE", 1)[-1].strip()[:360],
            )
        if "BOOT_JOB_SKIPPED" in text:
            self.boot_job_skipped += 1
            self.tag(
                "BOOT_JOB_SKIPPED",
                text.split("BOOT_JOB_SKIPPED", 1)[-1].strip()[:200],
            )
        if "ORIGIN_JOB_VMETHOD_ENTER" in text:
            self.origin_job_vmethod_enter += 1
            self.seq1_vmethod_enter += 1
            self.tag(
                "ORIGIN_JOB_VMETHOD_ENTER",
                text.split("ORIGIN_JOB_VMETHOD_ENTER", 1)[-1].strip()[:360],
            )
            if "rcxJobNodeMatch=1" in text:
                self.seq1_vmethod_rcx_match += 1
                self.seq1_target_with_node += 1
                m = re.search(r"\btarget=(\S+)", text)
                if m:
                    self.seq1_identified_target = m.group(1)
                    self.origin_identified_target = m.group(1)
        if "LSX_ORIGIN_JOB_TARGET_IDENTIFIED" in text:
            self.origin_job_target_identified += 1
            self.tag(
                "LSX_ORIGIN_JOB_TARGET_IDENTIFIED",
                text.split("LSX_ORIGIN_JOB_TARGET_IDENTIFIED", 1)[-1].strip()[:240],
            )
        if "LSX_JOB_VMETHOD_DISPATCH_CONFIRMED" in text:
            self.job_vmethod_dispatch_confirmed += 1
            self.tag(
                "LSX_JOB_VMETHOD_DISPATCH_CONFIRMED",
                text.split("LSX_JOB_VMETHOD_DISPATCH_CONFIRMED", 1)[-1].strip()[:240],
            )
        if "ORIGIN_JOB_VMETHOD_LEAVE" in text:
            self.origin_job_vmethod_leave += 1
            self.seq1_vmethod_leave += 1
            self.tag(
                "ORIGIN_JOB_VMETHOD_LEAVE",
                text.split("ORIGIN_JOB_VMETHOD_LEAVE", 1)[-1].strip()[:200],
            )
        if "ORIGIN_CALLBACK_SYNC_SIGNAL" in text:
            self.origin_callback_sync += 1
            self.seq1_callback_sync += 1
            self.seq1_sync += 1
            self.callback_sync += 1
            if "handleKind=secondary" in text:
                self.origin_callback_sync_secondary += 1
            self.tag(
                "ORIGIN_CALLBACK_SYNC_SIGNAL",
                text.split("ORIGIN_CALLBACK_SYNC_SIGNAL", 1)[-1].strip()[:280],
            )
        if "ORIGIN_SECONDARY_HANDLE" in text:
            self.origin_secondary_handle += 1
            self.tag(
                "ORIGIN_SECONDARY_HANDLE",
                text.split("ORIGIN_SECONDARY_HANDLE", 1)[-1].strip()[:220],
            )
        if "ORIGIN_POOL_HANDLE" in text:
            self.origin_pool_handle_seen += 1
            self.tag(
                "ORIGIN_POOL_HANDLE",
                text.split("ORIGIN_POOL_HANDLE", 1)[-1].strip()[:220],
            )
        if "ORIGIN_SECOND_WAIT_ENTER" in text:
            self.origin_second_wait_enter += 1
            self.tag(
                "ORIGIN_SECOND_WAIT_ENTER",
                text.split("ORIGIN_SECOND_WAIT_ENTER", 1)[-1].strip()[:280],
            )
        if "ORIGIN_SECOND_WAIT_WAKE" in text:
            self.origin_second_wait_wake += 1
            self.tag(
                "ORIGIN_SECOND_WAIT_WAKE",
                text.split("ORIGIN_SECOND_WAIT_WAKE", 1)[-1].strip()[:300],
            )
        if "SECOND_STAGE_WAKE_ONESHOT_ARMED" in text:
            self.second_stage_oneshot_armed += 1
            self.tag(
                "SECOND_STAGE_WAKE_ONESHOT_ARMED",
                text.split("SECOND_STAGE_WAKE_ONESHOT_ARMED", 1)[-1].strip()[:240],
            )
        if "LSX_ORIGIN_SECOND_REENTRY_HOOK_MISS" in text:
            self.second_reentry_hook_miss += 1
            self.tag(
                "LSX_ORIGIN_SECOND_REENTRY_HOOK_MISS",
                text.split("LSX_ORIGIN_SECOND_REENTRY_HOOK_MISS", 1)[-1].strip()[:240],
            )
        if "LSX_ORIGIN_SECOND_SYNC_HANDOFF_IDENTIFIED" in text:
            self.origin_second_sync_identified += 1
            self.tag(
                "LSX_ORIGIN_SECOND_SYNC_HANDOFF_IDENTIFIED",
                text.split("LSX_ORIGIN_SECOND_SYNC_HANDOFF_IDENTIFIED", 1)[-1].strip()[
                    :240
                ],
            )
        if "LSX_ORIGIN_SECOND_SYNC_HANDOFF_CONFIRMED" in text:
            self.second_sync_handoff_confirmed += 1
            self.origin_second_sync_identified += 1
            self.tag(
                "LSX_ORIGIN_SECOND_SYNC_HANDOFF_CONFIRMED",
                text.split("LSX_ORIGIN_SECOND_SYNC_HANDOFF_CONFIRMED", 1)[-1].strip()[
                    :240
                ],
            )
        if "SECOND_STAGE_REENTRY" in text and "awaiting SECOND_STAGE_REENTRY" not in text:
            # Count only the primary marker, not *_CONFIRMED / *_SKIP variants.
            if (
                "SECOND_STAGE_REENTRY_CONFIRMED" not in text
                and "SECOND_STAGE_REENTRY_SKIP" not in text
                and "LSX_ORIGIN_SECOND_STAGE_REENTRY" not in text
            ):
                self.second_stage_reentry += 1
            self.tag(
                "SECOND_STAGE_REENTRY",
                text.split("SECOND_STAGE_REENTRY", 1)[-1].strip()[:320],
            )
        if "LSX_ORIGIN_SECOND_STAGE_REENTRY_CONFIRMED" in text:
            self.tag(
                "LSX_ORIGIN_SECOND_STAGE_REENTRY_CONFIRMED",
                text.split("LSX_ORIGIN_SECOND_STAGE_REENTRY_CONFIRMED", 1)[-1].strip()[
                    :200
                ],
            )
        if "SECOND_STAGE_DISPATCH_ENTER" in text:
            self.second_stage_dispatch_enter += 1
            self.tag(
                "SECOND_STAGE_DISPATCH_ENTER",
                text.split("SECOND_STAGE_DISPATCH_ENTER", 1)[-1].strip()[:280],
            )
        if "LSX_ORIGIN_SECOND_STAGE_DISPATCH_IDENTIFIED" in text:
            self.tag(
                "LSX_ORIGIN_SECOND_STAGE_DISPATCH_IDENTIFIED",
                text.split("LSX_ORIGIN_SECOND_STAGE_DISPATCH_IDENTIFIED", 1)[-1].strip()[
                    :200
                ],
            )
        if "SECOND_STAGE_VMETHOD_DISPATCH" in text:
            if "SECOND_STAGE_VMETHOD_DISPATCH_NO_JOB" not in text:
                self.second_stage_vmethod_dispatch += 1
            self.tag(
                "SECOND_STAGE_VMETHOD_DISPATCH",
                text.split("SECOND_STAGE_VMETHOD_DISPATCH", 1)[-1].strip()[:300],
            )
        if "SECOND_STAGE_INDIRECT_CALL" in text:
            self.second_stage_indirect_call += 1
            self.tag(
                "SECOND_STAGE_INDIRECT_CALL",
                text.split("SECOND_STAGE_INDIRECT_CALL", 1)[-1].strip()[:300],
            )
        if "SECOND_STAGE_JOB_CANDIDATE" in text:
            self.second_stage_job_candidate += 1
            self.tag(
                "SECOND_STAGE_JOB_CANDIDATE",
                text.split("SECOND_STAGE_JOB_CANDIDATE", 1)[-1].strip()[:280],
            )
        if "SECOND_STAGE_CONTROL_TRANSFER" in text:
            self.second_stage_control_transfer += 1
            self.tag(
                "SECOND_STAGE_CONTROL_TRANSFER",
                text.split("SECOND_STAGE_CONTROL_TRANSFER", 1)[-1].strip()[:260],
            )
        if "LSX_ORIGIN_SECOND_STAGE_TARGET_IDENTIFIED" in text:
            self.tag(
                "LSX_ORIGIN_SECOND_STAGE_TARGET_IDENTIFIED",
                text.split("LSX_ORIGIN_SECOND_STAGE_TARGET_IDENTIFIED", 1)[-1].strip()[
                    :240
                ],
            )
        if "SECOND_STAGE_TARGET_ENTER" in text:
            self.second_stage_target_enter += 1
            self.tag(
                "SECOND_STAGE_TARGET_ENTER",
                text.split("SECOND_STAGE_TARGET_ENTER", 1)[-1].strip()[:280],
            )
        if "SECOND_WORKER_CONTEXT" in text:
            self.tag(
                "SECOND_WORKER_CONTEXT",
                text.split("SECOND_WORKER_CONTEXT", 1)[-1].strip()[:300],
            )
        if "SECOND_STAGE_UI_HANDOFF" in text:
            self.second_stage_ui += 1
            self.tag(
                "SECOND_STAGE_UI_HANDOFF",
                text.split("SECOND_STAGE_UI_HANDOFF", 1)[-1].strip()[:220],
            )
        if "SECOND_STAGE_SYNC_SIGNAL" in text:
            self.second_stage_sync += 1
            self.tag(
                "SECOND_STAGE_SYNC_SIGNAL",
                text.split("SECOND_STAGE_SYNC_SIGNAL", 1)[-1].strip()[:220],
            )
        if "SECOND_STAGE_ASYNC_QUEUE" in text:
            self.second_stage_async += 1
            self.tag(
                "SECOND_STAGE_ASYNC_QUEUE",
                text.split("SECOND_STAGE_ASYNC_QUEUE", 1)[-1].strip()[:220],
            )
        if "SECOND_STAGE_LSX_ACTIVITY" in text:
            self.second_stage_lsx += 1
            self.tag(
                "SECOND_STAGE_LSX_ACTIVITY",
                text.split("SECOND_STAGE_LSX_ACTIVITY", 1)[-1].strip()[:220],
            )
        if "ORIGIN_PAYLOAD_ENTER" in text:
            self.origin_payload_enter += 1
            self.origin_job_payload_enter += 1
            self.seq1_payload_target_enter += 1
            self.tag(
                "ORIGIN_PAYLOAD_ENTER",
                text.split("ORIGIN_PAYLOAD_ENTER", 1)[-1].strip()[:300],
            )
        if "ORIGIN_CALLBACK_UI_HANDOFF" in text:
            self.origin_callback_ui += 1
            self.seq1_callback_ui += 1
            self.seq1_ui += 1
            self.callback_ui += 1
            self.tag(
                "ORIGIN_CALLBACK_UI_HANDOFF",
                text.split("ORIGIN_CALLBACK_UI_HANDOFF", 1)[-1].strip()[:220],
            )
        if "ORIGIN_CALLBACK_ASYNC_QUEUE" in text:
            self.origin_callback_async += 1
            self.seq1_callback_async += 1
            self.seq1_async += 1
            self.callback_async += 1
            self.tag(
                "ORIGIN_CALLBACK_ASYNC_QUEUE",
                text.split("ORIGIN_CALLBACK_ASYNC_QUEUE", 1)[-1].strip()[:220],
            )
        if "ORIGIN_JOB_PAYLOAD_ENTER" in text:
            self.origin_job_payload_enter += 1
            self.seq1_payload_target_enter += 1
            self.tag(
                "ORIGIN_JOB_PAYLOAD_ENTER",
                text.split("ORIGIN_JOB_PAYLOAD_ENTER", 1)[-1].strip()[:280],
            )
        if "ORIGIN_VMETHOD_HOOKED" in text:
            self.seq1_vmethod_hooked += 1
            self.tag(
                "ORIGIN_VMETHOD_HOOKED",
                text.split("ORIGIN_VMETHOD_HOOKED", 1)[-1].strip()[:280],
            )
            m = re.search(r"\btarget=(\S+)", text)
            if m and not self.seq1_vmethod_target:
                self.seq1_vmethod_target = m.group(1)
        if "ORIGIN_VERSION_GATE HIT" in text:
            self.origin_version_gate_hits += 1
            self.tag(
                "ORIGIN_VERSION_GATE",
                text.split("ORIGIN_VERSION_GATE", 1)[-1].strip()[:200],
            )
        if "ORIGIN_VERSION_FIX" in text and "applied=1" in text:
            self.origin_version_fix_applied += 1
            self.tag(
                "ORIGIN_VERSION_FIX",
                text.split("ORIGIN_VERSION_FIX", 1)[-1].strip()[:200],
            )
        if "ORIGIN_AUTH_SETUP_RESULT" in text or "AUTHSETUP_RESULT_SITE" in text:
            m = re.search(r"(?:eax|ret)=?(0x[0-9a-fA-F]+)", text)
            if m:
                self.origin_auth_setup_eax = m.group(1)
            self.tag(
                "ORIGIN_AUTH_SETUP_RESULT",
                text.split("AUTHSETUP_RESULT", 1)[-1].strip()[:160]
                if "AUTHSETUP_RESULT" in text
                else text[:160],
            )
        if "AUTHSETUP_ENTER" in text:
            self.authsetup_enter += 1
            self.tag("AUTHSETUP_ENTER", text.split("AUTHSETUP_ENTER", 1)[-1].strip()[:220])
        if "AUTHSETUP_LEAVE" in text:
            self.authsetup_leave += 1
            m = re.search(r"\bret=(0x[0-9a-fA-F]+)", text)
            if m:
                self.authsetup_leave_ret = m.group(1)
            self.tag("AUTHSETUP_LEAVE", text.split("AUTHSETUP_LEAVE", 1)[-1].strip()[:200])
        if "AUTH_CALLSITE_717D68D_HIT" in text:
            self.auth_callsite_717d68d_hits += 1
            self.tag(
                "AUTH_CALLSITE_717D68D_HIT",
                text.split("AUTH_CALLSITE_717D68D_HIT", 1)[-1].strip()[:240],
            )
        if "ORIGIN_CHECK_ENTER" in text and "tid=" in text:
            self.origin_check_enter += 1
            m = re.search(r"\btid=(\d+)", text)
            if m:
                self.origin_check_tid = m.group(1)
            self.tag(
                "ORIGIN_CHECK_ENTER",
                text.split("ORIGIN_CHECK_ENTER", 1)[-1].strip()[:240],
            )
        if "ORIGIN_CHECK_LEAVE" in text and "tid=" in text:
            self.origin_check_leave_obs += 1
            self.tag(
                "ORIGIN_CHECK_LEAVE",
                text.split("ORIGIN_CHECK_LEAVE", 1)[-1].strip()[:240],
            )
        if "STALKER_ORIGIN_START" in text:
            self.stalker_origin_start += 1
            self.tag(
                "STALKER_ORIGIN_START",
                text.split("STALKER_ORIGIN_START", 1)[-1].strip()[:160],
            )
        if "STALKER_UI_START" in text:
            self.ui_stalker_start += 1
            self.tag(
                "STALKER_UI_START",
                text.split("STALKER_UI_START", 1)[-1].strip()[:160],
            )
        if "FIFA_WINDOW_THREAD" in text:
            m = re.search(r"\btid=(\d+)", text)
            if m:
                self.fifa_window_tid = m.group(1)
            self.tag(
                "FIFA_WINDOW_THREAD",
                text.split("FIFA_WINDOW_THREAD", 1)[-1].strip()[:200],
            )
        if "UI_MESSAGE_HANDOFF" in text:
            self.ui_handoff_msg += 1
            self.tag(
                "UI_MESSAGE_HANDOFF",
                text.split("UI_MESSAGE_HANDOFF", 1)[-1].strip()[:240],
            )
        if "ASYNC_CALLBACK_QUEUED" in text:
            self.ui_handoff_async += 1
            self.tag(
                "ASYNC_CALLBACK_QUEUED",
                text.split("ASYNC_CALLBACK_QUEUED", 1)[-1].strip()[:240],
            )
        if "ASYNC_CALLBACK_ENTER" in text:
            self.async_callback_enter += 1
            self.tag(
                "ASYNC_CALLBACK_ENTER",
                text.split("ASYNC_CALLBACK_ENTER", 1)[-1].strip()[:220],
            )
        if "SYNC_SIGNAL" in text or "SYNC_WAIT_WAKE" in text or "SYNC_HANDOFF_CORRELATED" in text:
            self.ui_handoff_sync += 1
            self.tag(
                "SYNC_SIGNAL",
                text.split("SYNC_", 1)[-1].strip()[:240],
            )
        if "JOB_ENQUEUE_SIGNAL" in text:
            self.job_enqueue += 1
            self.tag(
                "JOB_ENQUEUE_SIGNAL",
                text.split("JOB_ENQUEUE_SIGNAL", 1)[-1].strip()[:300],
            )
        if "JOB_SEQ1_NODE_CAPTURE" in text:
            self.seq1_node_capture += 1
            self.tag(
                "JOB_SEQ1_NODE_CAPTURE",
                text.split("JOB_SEQ1_NODE_CAPTURE", 1)[-1].strip()[:320],
            )
        if "JOB_SEQ1_SKIP" in text:
            self.tag(
                "JOB_SEQ1_SKIP",
                text.split("JOB_SEQ1_SKIP", 1)[-1].strip()[:240],
            )
        if "SEQ1_VMETHOD_HOOKED" in text:
            self.seq1_vmethod_hooked += 1
            self.tag(
                "SEQ1_VMETHOD_HOOKED",
                text.split("SEQ1_VMETHOD_HOOKED", 1)[-1].strip()[:280],
            )
            m = re.search(r"\btarget=(\S+)", text)
            if m and not self.seq1_vmethod_target:
                self.seq1_vmethod_target = m.group(1)
        if "SEQ1_VMETHOD_ENTER" in text:
            self.seq1_vmethod_enter += 1
            self.tag(
                "SEQ1_VMETHOD_ENTER",
                text.split("SEQ1_VMETHOD_ENTER", 1)[-1].strip()[:360],
            )
            if "rcxJobNodeMatch=1" in text or "jobNodeMatch=1" in text:
                self.seq1_target_with_node += 1
                if "rcxJobNodeMatch=1" in text:
                    self.seq1_vmethod_rcx_match += 1
                m = re.search(r"\btarget=(\S+)", text)
                if m:
                    self.seq1_identified_target = m.group(1)
                    self.seq1_vmethod_target = m.group(1)
        if "SEQ1_VMETHOD_GENERIC" in text:
            self.seq1_vmethod_generic += 1
            self.tag(
                "SEQ1_VMETHOD_GENERIC",
                text.split("SEQ1_VMETHOD_GENERIC", 1)[-1].strip()[:240],
            )
        if "SEQ1_VMETHOD_LEAVE" in text:
            self.seq1_vmethod_leave += 1
            self.tag(
                "SEQ1_VMETHOD_LEAVE",
                text.split("SEQ1_VMETHOD_LEAVE", 1)[-1].strip()[:200],
            )
        if "SEQ1_PAYLOAD_TARGET_ENTER" in text:
            self.seq1_payload_target_enter += 1
            self.tag(
                "SEQ1_PAYLOAD_TARGET_ENTER",
                text.split("SEQ1_PAYLOAD_TARGET_ENTER", 1)[-1].strip()[:280],
            )
        if "SEQ1_CALLBACK_SYNC" in text:
            self.seq1_callback_sync += 1
            self.seq1_sync += 1
            self.callback_sync += 1
            self.tag(
                "SEQ1_CALLBACK_SYNC",
                text.split("SEQ1_CALLBACK_SYNC", 1)[-1].strip()[:220],
            )
        if "SEQ1_CALLBACK_UI_HANDOFF" in text:
            self.seq1_callback_ui += 1
            self.seq1_ui += 1
            self.callback_ui += 1
            self.tag(
                "SEQ1_CALLBACK_UI_HANDOFF",
                text.split("SEQ1_CALLBACK_UI_HANDOFF", 1)[-1].strip()[:220],
            )
        if "SEQ1_CALLBACK_ASYNC_QUEUE" in text:
            self.seq1_callback_async += 1
            self.seq1_async += 1
            self.callback_async += 1
            self.tag(
                "SEQ1_CALLBACK_ASYNC_QUEUE",
                text.split("SEQ1_CALLBACK_ASYNC_QUEUE", 1)[-1].strip()[:220],
            )
        if "STALKER_SEQ1_CALLBACK_START" in text:
            self.tag(
                "STALKER_SEQ1_CALLBACK_START",
                text.split("STALKER_SEQ1_CALLBACK_START", 1)[-1].strip()[:200],
            )
        if "SEQ1_CONTROL_TRANSFER" in text:
            self.seq1_control_transfer += 1
            self.tag(
                "SEQ1_CONTROL_TRANSFER",
                text.split("SEQ1_CONTROL_TRANSFER", 1)[-1].strip()[:320],
            )
            if "jobNodeMatch=1" in text or "jobNodeFieldMatch=1" in text:
                if "kind=jmp-indirect" in text:
                    self.seq1_tailcall_with_node += 1
                m = re.search(r"\btarget=(\S+)", text)
                if m and not self.seq1_identified_target:
                    self.seq1_identified_target = m.group(1)
        if "SEQ1_TARGET_ENTER" in text:
            self.seq1_target_enter += 1
            self.tag(
                "SEQ1_TARGET_ENTER",
                text.split("SEQ1_TARGET_ENTER", 1)[-1].strip()[:300],
            )
            if "jobNodeInArgs=1" in text:
                self.seq1_target_with_node += 1
                m = re.search(r"\btarget=(\S+)", text)
                if m:
                    self.seq1_identified_target = m.group(1)
        if "SEQ1_SYNC_SIGNAL" in text:
            self.seq1_sync += 1
            self.callback_sync += 1
            self.tag(
                "SEQ1_SYNC_SIGNAL",
                text.split("SEQ1_SYNC_SIGNAL", 1)[-1].strip()[:220],
            )
        if "SEQ1_UI_HANDOFF" in text:
            self.seq1_ui += 1
            self.callback_ui += 1
            self.tag(
                "SEQ1_UI_HANDOFF",
                text.split("SEQ1_UI_HANDOFF", 1)[-1].strip()[:220],
            )
        if "SEQ1_ASYNC_QUEUE" in text:
            self.seq1_async += 1
            self.callback_async += 1
            self.tag(
                "SEQ1_ASYNC_QUEUE",
                text.split("SEQ1_ASYNC_QUEUE", 1)[-1].strip()[:220],
            )
        if "SEQ1_GLOBAL_WRITE" in text:
            self.seq1_global_write += 1
            self.callback_global_write += 1
            self.tag(
                "SEQ1_GLOBAL_WRITE",
                text.split("SEQ1_GLOBAL_WRITE", 1)[-1].strip()[:240],
            )
        if "JOB_SEQ1_ENQUEUE" in text:
            self.job_seq1_enqueue += 1
            self.job_enqueue += 1
            self.tag(
                "JOB_SEQ1_ENQUEUE",
                text.split("JOB_SEQ1_ENQUEUE", 1)[-1].strip()[:300],
            )
        if "JOB_SEQ1_WAKE" in text:
            self.job_seq1_wake += 1
            self.job_wake += 1
            self.tag(
                "JOB_SEQ1_WAKE",
                text.split("JOB_SEQ1_WAKE", 1)[-1].strip()[:300],
            )
        if "JOB_DISPATCH_ENTER" in text:
            self.job_dispatch_enter += 1
            self.tag(
                "JOB_DISPATCH_ENTER",
                text.split("JOB_DISPATCH_ENTER", 1)[-1].strip()[:320],
            )
        if "JOB_POST_DISPATCH_CALL" in text:
            self.tag(
                "JOB_POST_DISPATCH_CALL",
                text.split("JOB_POST_DISPATCH_CALL", 1)[-1].strip()[:280],
            )
            if "targetIs5380960=1" in text:
                self.job_callback_enter += 1
                self.job_callback_target = "FIFA17.exe+0x5380960"
            elif not self.job_callback_target:
                m = re.search(r"\btargetApprox=(\S+)", text)
                if m:
                    self.job_callback_target = m.group(1)
                    self.job_callback_dispatch += 1
        if "JOB_CALLBACK_DISPATCH" in text:
            self.job_callback_dispatch += 1
            m = re.search(r"\btarget=(\S+)", text)
            if m and not self.job_callback_target:
                self.job_callback_target = m.group(1)
            if "rcxMatchesSeq1=1" in text:
                self.job_callback_rcx_match += 1
            if "matchWakeTid=1" in text:
                self.job_callback_wake_tid_match += 1
            self.tag(
                "JOB_CALLBACK_DISPATCH",
                text.split("JOB_CALLBACK_DISPATCH", 1)[-1].strip()[:320],
            )
        if "JOB_CALLBACK_ENTER" in text:
            self.job_callback_enter += 1
            if "rcxMatchesSeq1=1" in text or "anyCtxMatch=1" in text:
                self.job_callback_rcx_match += 1
            if "matchWakeTid=1" in text:
                self.job_callback_wake_tid_match += 1
            self.tag(
                "JOB_CALLBACK_ENTER",
                text.split("JOB_CALLBACK_ENTER", 1)[-1].strip()[:320],
            )
        if "JOB_CTX_MATCH" in text:
            self.job_ctx_match += 1
            self.tag(
                "JOB_CTX_MATCH",
                text.split("JOB_CTX_MATCH", 1)[-1].strip()[:200],
            )
        if "CALLBACK_SYNC_SIGNAL" in text:
            self.callback_sync += 1
            self.tag(
                "CALLBACK_SYNC_SIGNAL",
                text.split("CALLBACK_SYNC_SIGNAL", 1)[-1].strip()[:220],
            )
        if "CALLBACK_UI_HANDOFF" in text:
            self.callback_ui += 1
            self.tag(
                "CALLBACK_UI_HANDOFF",
                text.split("CALLBACK_UI_HANDOFF", 1)[-1].strip()[:220],
            )
        if "CALLBACK_ASYNC_QUEUE" in text:
            self.callback_async += 1
            self.tag(
                "CALLBACK_ASYNC_QUEUE",
                text.split("CALLBACK_ASYNC_QUEUE", 1)[-1].strip()[:220],
            )
        if "CALLBACK_GLOBAL_WRITE" in text:
            self.callback_global_write += 1
            self.tag(
                "CALLBACK_GLOBAL_WRITE",
                text.split("CALLBACK_GLOBAL_WRITE", 1)[-1].strip()[:240],
            )
        if "JOB_WORKER_WAKE" in text:
            self.job_wake += 1
            self.tag(
                "JOB_WORKER_WAKE",
                text.split("JOB_WORKER_WAKE", 1)[-1].strip()[:300],
            )
        if "JOB_INDIRECT_CALL" in text:
            self.job_indirect += 1
            m = re.search(r"\btarget=(\S+)", text)
            if m and not self.job_indirect_target:
                self.job_indirect_target = m.group(1)
            self.tag(
                "JOB_INDIRECT_CALL",
                text.split("JOB_INDIRECT_CALL", 1)[-1].strip()[:320],
            )
        if "CANDIDATE_PTR" in text:
            self.tag(
                "CANDIDATE_PTR",
                text.split("CANDIDATE_PTR", 1)[-1].strip()[:280],
            )
        if "ORIGIN_HANDOFF_WINDOW_START" in text:
            self.tag(
                "ORIGIN_HANDOFF_WINDOW_START",
                text.split("ORIGIN_HANDOFF_WINDOW_START", 1)[-1].strip()[:120],
            )
        if "VERSION_SCAN_FOUND" in text or "VERSION_TEXT_FOUND" in text:
            self.version_text_found += 1
            if "credible=1" in text or "Votre version" in text or "TXT_ORIGIN" in text:
                self.version_scan_credible += 1
            self.tag(
                "VERSION_SCAN_FOUND",
                text.split("VERSION_SCAN_FOUND", 1)[-1].strip()[:220]
                if "VERSION_SCAN_FOUND" in text
                else text.split("VERSION_TEXT_FOUND", 1)[-1].strip()[:220],
            )
        if "VERSION_TEXT_READ" in text or (
            "VERSION_TEXT_ACCESS" in text and "operation=read" in text
        ):
            self.version_text_reads += 1
            self.tag(
                "VERSION_TEXT_ACCESS",
                text.split("VERSION_TEXT_ACCESS", 1)[-1].strip()[:220]
                if "VERSION_TEXT_ACCESS" in text
                else text.split("VERSION_TEXT_READ", 1)[-1].strip()[:220],
            )
        if "VERSION_TEXT_ACCESS" in text and "operation=write" in text:
            self.version_text_writes += 1
            self.tag(
                "VERSION_TEXT_ACCESS",
                text.split("VERSION_TEXT_ACCESS", 1)[-1].strip()[:220],
            )
        if "VERSION_ERROR_IMM" in text or "VERSION_ERROR_IMMEDIATE" in text:
            self.version_error_imm += 1
            self.tag(
                "VERSION_ERROR_IMM",
                text.split("VERSION_ERROR_IMM", 1)[-1].strip()[:220],
            )
        if "VERSION_ERROR_RETURN" in text:
            self.version_error_ret += 1
            self.tag(
                "VERSION_ERROR_RETURN",
                text.split("VERSION_ERROR_RETURN", 1)[-1].strip()[:220],
            )
        if "VERSION_TOKEN_XREF_HIT" in text:
            self.version_token_xref_hits += 1
            self.tag(
                "VERSION_TOKEN_XREF_HIT",
                text.split("VERSION_TOKEN_XREF_HIT", 1)[-1].strip()[:240],
            )
        if "LOCALIZE_TOKEN" in text:
            self.localize_token_seen = True
            self.tag("LOCALIZE_TOKEN", text.split("LOCALIZE_TOKEN", 1)[-1].strip()[:200])
        if "POPUP_DISPATCH" in text:
            self.popup_dispatch_seen = True
            self.tag("POPUP_DISPATCH", text.split("POPUP_DISPATCH", 1)[-1].strip()[:200])
        if (
            "GetAuthCode" in text
            or "GetAuthToken" in text
            or "STP4216_AUTHCODE" in text
            or "OriginRequestAuthCode" in text
        ) and not self.get_authcode_seen:
            if (
                "Request" in text
                or "AUTHCODE" in text
                or "GetAuth" in text
                or "OriginRequestAuthCode" in text
            ):
                self.get_authcode_seen = True
                self.tag("STP_GET_AUTHCODE", "seen=1 " + text[:160])
        if (
            "BLAZE_AUTH10" in text
            or "Auth/10" in text
            or re.search(r"\bAUTH[_ ]?10\b", text, re.I)
            or re.search(r"component[=:]?\s*1\b.*command[=:]?\s*10\b", text, re.I)
        ):
            if not self.blaze_auth10_seen:
                self.blaze_auth10_seen = True
                self.tag("BLAZE_AUTH10", "seen=1 " + text[:160])
        if "LSX_RESTORE_VERDICT" in text:
            m = re.search(r"\bverdict=(\S+)", text)
            if m:
                self.lsx_restore_verdict = m.group(1)
        self._handle(text)

    def handshake_stage_verdict(self) -> str:
        """Map last :4216 handshake stage to a precise LSX_* verdict."""
        if not self.hs_dll_loaded:
            return "LSX_STP_DLL_NOT_LOADED"
        if not self.hs_bind_4216:
            return "LSX_STP_SERVER_NOT_STARTED"
        if self.hs_listen_4216 and not self.hs_client_connect and not self.hs_accept:
            return "LSX_CLIENT_CONNECT_MISS"
        if (self.hs_client_connect or self.hs_accept) and not self.hs_challenge:
            return "LSX_CHALLENGE_SEND_MISS"
        if self.hs_challenge and not self.hs_challenge_response:
            return "LSX_CHALLENGE_RESPONSE_MISS"
        if self.hs_challenge_response and not self.hs_challenge_accepted:
            if self.hs_socket_closed:
                return "LSX_HANDSHAKE_SOCKET_CLOSED_EARLY"
            return "LSX_CHALLENGE_ACCEPT_REJECTED"
        if self.hs_challenge_accepted and not self.hs_session_key:
            return "LSX_SESSION_KEY_DERIVATION_MISS"
        if self.hs_session_key:
            return "LSX_HANDSHAKE_OK"
        if self.hs_socket_closed and not self.hs_challenge_accepted:
            return "LSX_HANDSHAKE_SOCKET_CLOSED_EARLY"
        return "LSX_HANDSHAKE_FLAKY_CONFIRMED"

    def tag(self, name: str, msg: str) -> None:
        self.out_raw(f"[stp4216] ★★★ {name} {msg}")

    def out_raw(self, text: str) -> None:
        """Write without re-entrant _handle."""
        print(text)
        self.lines.append(text)
        try:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError:
            pass

    def _extract_json_field(self, text: str, key: str) -> str | None:
        idx = text.find(key + "=")
        if idx < 0:
            return None
        rest = text[idx + len(key) + 1 :]
        if rest.startswith('"'):
            try:
                val, _ = json.JSONDecoder().raw_decode(rest)
                return val if isinstance(val, str) else None
            except Exception:
                return None
        m = re.match(r"(\S+)", rest)
        return m.group(1) if m else None

    def _handle(self, text: str) -> None:
        # Handshake plaintext only from HANDSHAKE lines (avoid double with PLAIN_*)
        if "STP4216_HANDSHAKE" in text:
            xml = self._extract_json_field(text, "xml")
            if xml:
                self.tracker.on_plaintext(xml)
                self._emit_message(text, xml, encrypted=False)
                if "ChallengeResponse" in xml and self.tracker.session and not self.session_key_logged:
                    self.tag(
                        "STP4216_SESSION_KEY",
                        f"keyHex={self.tracker.session.key.hex()} ready={self.tracker.ready} "
                        f"source={self.tracker.key_source} "
                        f"clientResp={self.tracker.client_response_hex!r} "
                        f"acceptedResp={self.tracker.accepted_response_hex!r}",
                    )
                    self.session_key_logged = True
                if "ChallengeAccepted" in xml and self.tracker.session:
                    self.tag(
                        "STP4216_SESSION_KEY",
                        f"keyHex={self.tracker.session.key.hex()} ready={self.tracker.ready} "
                        f"source={self.tracker.key_source} "
                        f"clientResp={self.tracker.client_response_hex!r} "
                        f"acceptedResp={self.tracker.accepted_response_hex!r}",
                    )
                    self.session_key_logged = True

        if "STP4216_CIPHER_" in text and "hexAscii=" in text:
            hx = self._extract_json_field(text, "hexAscii")
            if not hx:
                m = re.search(r"hexAscii=([0-9a-fA-F]+)", text)
                hx = m.group(1) if m else None
            if not hx:
                return
            flow_m = re.search(r"\bflow=(\S+)", text)
            flow = flow_m.group(1) if flow_m else "?"
            fd_m = re.search(r"\bfd=(\d+)", text)
            fd = fd_m.group(1) if fd_m else "?"
            seq_m = re.search(r"\bseq=(\d+)", text)
            seq = seq_m.group(1) if seq_m else "?"
            plain, key_mode = self.tracker.try_decrypt_hex_ascii_dual(
                hx, protocol_version=self.sdk_protocol_version
            )
            self.decrypt_key_modes[key_mode] = self.decrypt_key_modes.get(key_mode, 0) + 1
            self.tag(
                "STP4216_DECRYPT_KEY_MODE",
                f"seq={seq} fd={fd} flow={flow} mode={key_mode} "
                f"protocolVersion={self.sdk_protocol_version!r} hexLen={len(hx)}",
            )
            if plain is None or not plain.lstrip().startswith(("<LSX>", "<?xml")):
                self.decrypt_fail += 1
                self.tag(
                    "STP4216_DECRYPT_FAIL",
                    f"seq={seq} fd={fd} flow={flow} hexLen={len(hx)} ready={self.tracker.ready} "
                    f"mode={key_mode} protocolVersion={self.sdk_protocol_version!r}",
                )
                return
            try:
                ET.fromstring(plain)
                parse_ok = True
            except ET.ParseError:
                parse_ok = False
            self.decrypt_ok += 1
            self.tag(
                "STP4216_DECRYPT_OK",
                f"seq={seq} fd={fd} flow={flow} len={len(plain)} xmlParse={int(parse_ok)} "
                f"keyMode={key_mode}",
            )
            plain_tag = "STP4216_PLAIN_OUT" if flow == "STP_TO_FIFA" else "STP4216_PLAIN_IN"
            self.tag(
                plain_tag,
                f"seq={seq} fd={fd} flow={flow} via=decrypt keyMode={key_mode} "
                f"xml={json.dumps(plain, ensure_ascii=False)}",
            )
            self._emit_message(text, plain, encrypted=True)

    def _emit_challenge_response(self, xml: str) -> None:
        keys = [
            "ContentId",
            "contentId",
            "Title",
            "title",
            "MultiplayerId",
            "multiplayerId",
            "Language",
            "language",
            "Version",
            "version",
            "ProtocolVersion",
            "protocolVersion",
            "SdkVersion",
            "sdkVersion",
            "key",
            "response",
            "GameId",
            "gameId",
            "ProductId",
            "productId",
            "build",
        ]
        meta = {}
        for k in keys:
            v = attr(xml, k)
            if v:
                meta[k] = v
        for k in ("ContentId", "Title", "MultiplayerId", "Language", "Version"):
            m = re.search(rf"<{k}>([^<]*)</{k}>", xml, re.I)
            if m:
                meta[k] = m.group(1)
        # origin-sdk: @version = protocol, <Version> = SDK
        proto = attr(xml, "version")  # attribute on ChallengeResponse
        sdk_el = None
        m = re.search(r"<Version>([^<]*)</Version>", xml, re.I)
        if m:
            sdk_el = m.group(1)
        meta["recipient"] = attr(xml, "recipient")
        meta["sender"] = attr(xml, "sender")
        meta["id"] = attr(xml, "id")
        if proto:
            meta["protocolVersionAttr"] = proto
            self.sdk_protocol_version = proto
        if sdk_el:
            meta["sdkVersionElement"] = sdk_el
            self.sdk_version = sdk_el
        self.challenge_meta = meta
        for k in ("ContentId", "MultiplayerId", "Title", "Language"):
            v = meta.get(k) or meta.get(k[0].lower() + k[1:])
            if v:
                self.identity[k] = v
        # FIRST priority tag for PROTOCOL_AUDIT
        self.tag(
            "STP4216_PROTOCOL_VERSION",
            f"protocolVersion={proto!r} sdkVersion={sdk_el!r} "
            f"contentId={meta.get('ContentId') or meta.get('contentId')!r} "
            f"multiplayerId={meta.get('MultiplayerId') or meta.get('multiplayerId')!r} "
            f"title={meta.get('Title') or meta.get('title')!r} "
            f"language={meta.get('Language') or meta.get('language')!r} "
            f"assumeV3={int((proto or '3') == '3')} "
            f"tryDefaultKey={int(bool(proto and proto != '3'))}",
        )
        self.tag(
            "STP4216_CHALLENGE_RESPONSE",
            " ".join(f"{k}={v!r}" for k, v in meta.items() if v),
        )
        self.tag(
            "STP4216_SDK_VERSION",
            f"protocolVersion={proto!r} sdkVersion={sdk_el!r} "
            f"ContentId={meta.get('ContentId') or meta.get('contentId')!r} "
            f"MultiplayerId={meta.get('MultiplayerId') or meta.get('multiplayerId')!r} "
            f"Title={meta.get('Title') or meta.get('title')!r} "
            f"Language={meta.get('Language') or meta.get('language')!r}",
        )
        self.tag(
            "STP4216_GAME_METADATA",
            f"ContentId={meta.get('ContentId') or meta.get('contentId')!r} "
            f"Title={meta.get('Title') or meta.get('title')!r} "
            f"MultiplayerId={meta.get('MultiplayerId') or meta.get('multiplayerId')!r} "
            f"Language={meta.get('Language') or meta.get('language')!r} "
            f"SdkVersion={sdk_el!r} ProtocolVersion={proto!r}",
        )

    def _emit_message(self, raw_line: str, xml: str, encrypted: bool) -> None:
        self.order += 1
        flow_m = re.search(r"\bflow=(\S+)", raw_line)
        flow = flow_m.group(1) if flow_m else "?"
        kind = "Event"
        if "<Request" in xml:
            kind = "Request"
        elif "<Response" in xml:
            kind = "Response"
        elif "<Event" in xml:
            kind = "Event"
        btype = body_type(xml)
        mid = attr(xml, "id")
        sender = attr(xml, "sender")
        recipient = attr(xml, "recipient")
        common = (
            f"order={self.order} direction={flow} kind={kind} id={mid} "
            f"recipient={recipient} sender={sender} "
            f"bodyType={btype} encrypted={int(encrypted)} xml={json.dumps(xml, ensure_ascii=False)}"
        )
        self.tag("STP4216_MESSAGE", common)
        if kind == "Request":
            self.tag("STP4216_REQUEST", common)
            if not mid:
                self.request_without_id += 1
                self.tag("STP4216_ID_MATCH", f"warn=request_missing_id bodyType={btype}")
            else:
                self.pending_requests[mid] = {
                    "bodyType": btype,
                    "recipient": recipient,
                    "order": str(self.order),
                }
                self.tag(
                    "STP4216_ID_MATCH",
                    f"pendingRequest id={mid} bodyType={btype} recipient={recipient!r}",
                )
            if not recipient:
                self.tag("STP4216_ID_MATCH", f"warn=request_missing_recipient id={mid} bodyType={btype}")
            # After GetConfig rewrite: track recipient occupancy (primary Test 2 criterion)
            if self.config_rewrite_sent or self.saw_config_true or "GetConfigResponse" in self.messages:
                if btype not in ("Challenge", "ChallengeResponse", "GetConfig"):
                    self.recipients_after_config.append(f"{btype}:{recipient or 'EMPTY'}")
                    if recipient:
                        self.nonempty_recipient_after_config += 1
                        self.tag(
                            "STP_CONFIG_RECIPIENT",
                            f"bodyType={btype} recipient={recipient!r} nonempty=1",
                        )
                        if self.nonempty_recipient_after_config == 1:
                            self.tag(
                                "STP_CONFIG_MAP_ACCEPTED",
                                f"firstNonempty bodyType={btype} recipient={recipient!r}",
                            )
                    else:
                        self.empty_recipient_after_config += 1
                        self.tag(
                            "STP_CONFIG_RECIPIENT",
                            f"bodyType={btype} recipient='' nonempty=0",
                        )
        elif kind == "Response":
            self.tag("STP4216_RESPONSE", common)
            if not mid:
                self.response_without_id += 1
                self.tag("STP4216_ID_MATCH", f"warn=response_missing_id bodyType={btype} sender={sender!r}")
            elif mid in self.pending_requests:
                req = self.pending_requests.pop(mid)
                self.id_match_ok += 1
                self.tag(
                    "STP4216_ID_MATCH",
                    f"ok=1 id={mid} request={req.get('bodyType')}→{btype} "
                    f"reqRecipient={req.get('recipient')!r} respSender={sender!r}",
                )
            else:
                self.id_match_fail += 1
                self.tag(
                    "STP4216_ID_MATCH",
                    f"ok=0 unmatchedResponse id={mid} bodyType={btype} sender={sender!r}",
                )
            if not sender:
                self.tag("STP4216_ID_MATCH", f"warn=response_missing_sender id={mid} bodyType={btype}")
            # Login must NOT be a Response
            if re.search(r"<Login\b", xml, re.I) and re.search(r"\bIsLoggedIn=", xml, re.I):
                self.login_as_response = True
                self.tag(
                    "STP4216_LOGIN_EVENT",
                    f"WRONG_ENVELOPE Login inside Response id={mid} — client expects Event",
                )
        else:
            self.tag("STP4216_EVENT", common)
            if mid:
                self.event_with_id += 1
                self.tag(
                    "STP4216_ID_MATCH",
                    f"warn=event_has_id id={mid} bodyType={btype} sender={sender!r} "
                    f"(Events should have no request id)",
                )
            if not sender:
                self.tag("STP4216_ID_MATCH", f"warn=event_missing_sender bodyType={btype}")
        self.messages.append(btype)

        if btype == "ChallengeResponse" or "ChallengeResponse" in xml:
            self._emit_challenge_response(xml)

        if btype in ("GetConfig", "GetConfigResponse") or "GetConfigResponse" in xml:
            self.tag("STP4216_GETCONFIG", f"bodyType={btype} xml={json.dumps(xml, ensure_ascii=False)}")
            if 'Config="true"' in xml or "Config='true'" in xml:
                self.saw_config_true = True
                self.tag("STP_CONFIG_MAP_ACCEPTED", "Config=true seen on wire")
            facs = parse_facilities(xml)
            if facs:
                for name, recip in facs:
                    self.facilities[name.upper()] = recip
                mapped = " ".join(f"{n}→{r}" for n, r in facs)
                self.tag("STP4216_GETCONFIG_MAP", f"count={len(facs)} map={mapped}")
                self.tag("STP4216_CONFIG_MAP", f"count={len(facs)} map={mapped}")
                self.tag("STP4216_CONFIG_ROUTES", f"map={mapped}")
                for need in (
                    "SDK",
                    "PROFILE",
                    "LOGIN",
                    "LOGIN_EVENT",
                    "ONLINE_STATUS_EVENT",
                    "PROFILE_EVENT",
                    "PRESENCE_EVENT",
                    "UTILITY",
                    "PRESENCE",
                    "EALS_EVENTS",
                ):
                    hit = self.facilities.get(need, "MISSING")
                    self.tag("STP4216_CONFIG_ROUTES", f"facility={need} recipient={hit}")
                    self.tag("STP4216_CONFIG_MAP", f"facility={need} recipient={hit}")
                    self.tag("STP4216_EVENT_ROUTE", f"facility={need} recipient={hit}")

        # MiddlewareConnectResult — old-SDK pre-login signal
        if btype == "MiddlewareConnectResult" or "MiddlewareConnectResult" in xml:
            reason = attr(xml, "reason")
            self.middleware_reason = reason
            self.tag(
                "STP4216_MIDDLEWARE_RESULT",
                f"reason={reason!r} sender={sender!r} kind={kind} "
                f"xml={json.dumps(xml, ensure_ascii=False)}",
            )

        # GetSettings / GetSetting — IsManualOffline priority
        if btype in ("GetSettings", "GetSettingsResponse", "GetSetting", "GetSettingResponse") or (
            "IsManualOffline" in xml or "IS_MANUAL_OFFLINE" in xml
        ):
            setting_id = attr(xml, "SettingId") or attr(xml, "Setting")
            manual = attr(xml, "IsManualOffline")
            if not manual and setting_id and "MANUAL_OFFLINE" in setting_id.upper():
                manual = attr(xml, "value") or attr(xml, "Setting") or attr(xml, "Value")
            if manual != "":
                if manual is not None and manual != "":
                    self.manual_offline = manual
            if "IsManualOffline=" in xml or "IsManualOffline" in xml:
                m = re.search(r'IsManualOffline="([^"]*)"', xml, re.I)
                if m:
                    self.manual_offline = m.group(1)
            self.tag(
                "STP4216_MANUAL_OFFLINE",
                f"bodyType={btype} SettingId={setting_id!r} IsManualOffline={self.manual_offline!r} "
                f"sender={attr(xml,'sender')!r} xml={json.dumps(xml, ensure_ascii=False)}",
            )

        if btype in ("GetInternetConnectedState", "InternetConnectedState"):
            connected = attr(xml, "connected")  # lowercase exact; integer "1"/"0"
            connected_alt = attr(xml, "Connected")
            self.online_connected = connected if connected != "" else connected_alt
            if btype == "GetInternetConnectedState" or (
                kind == "Request" and "GetInternetConnectedState" in xml
            ):
                self.get_internet_connected_seen += 1
            self.tag(
                "STP4216_CONNECTED",
                f"bodyType={btype} connected={connected!r} Connected={connected_alt!r} "
                f"sender={sender!r} xml={json.dumps(xml, ensure_ascii=False)}",
            )
            self.tag(
                "STP4216_CONNECTED_STATE",
                f"bodyType={btype} connected={connected!r} Connected={connected_alt!r} "
                f"sender={sender!r} xml={json.dumps(xml, ensure_ascii=False)}",
            )
            self.tag(
                "STP4216_ONLINE_RESPONSE",
                f"bodyType={btype} connected={self.online_connected!r} xml={json.dumps(xml, ensure_ascii=False)}",
            )
            if str(self.online_connected).strip() in ("1", "true", "True"):
                self.tag(
                    "STP_CONNECTED_1",
                    f"bodyType={btype} connected={self.online_connected!r} sender={sender!r}",
                )

        if btype == "GoOnline" or (kind == "Request" and "GoOnline" in xml):
            self.goonline_seen = True
            self.tag("STP4216_GOONLINE", f"phase=request {common}")
            self.tag("STP4216_GOONLINE_RESULT", f"phase=request {common}")
            self.tag("STP_GOONLINE", f"phase=request {common}")

        if btype == "ErrorSuccess" or "ErrorSuccess" in xml:
            code = attr(xml, "Code") or attr(xml, "code")
            desc = attr(xml, "Description") or attr(xml, "description")
            self.error_success_codes.append(code or "?")
            recent = self.messages[-3:] if self.messages else []
            payload = (
                f"Code={code!r} Description={desc!r} id={mid!r} sender={sender!r} "
                f"pending={int(code == '1')} success={int(code in ('0', '1', ''))} "
                f"xml={json.dumps(xml, ensure_ascii=False)}"
            )
            if "GoOnline" in recent or self.goonline_seen:
                self.goonline_code = code
                self.tag("STP4216_GOONLINE", payload)
                self.tag("STP4216_GOONLINE_RESULT", payload)
                self.tag("STP_GOONLINE", payload)
            else:
                self.tag("STP4216_GOONLINE_RESULT", f"ErrorSuccess unrelated? {payload}")

        # OnlineStatusEvent — exact attr isOnline (camelCase)
        if re.search(r"<OnlineStatusEvent\b", xml, re.I):
            self.saw_online_event = True
            is_online = attr(xml, "isOnline")
            is_online_alt = attr(xml, "IsOnline") or attr(xml, "online")
            self.online_event_is_online = is_online if is_online != "" else is_online_alt
            self.tag(
                "STP4216_ONLINE_EVENT",
                f"isOnline={is_online!r} IsOnline={is_online_alt!r} sender={sender!r} "
                f"xml={json.dumps(xml, ensure_ascii=False)}",
            )
            self.tag(
                "STP_ONLINE_EVENT",
                f"isOnline={is_online!r} IsOnline={is_online_alt!r} sender={sender!r}",
            )
            self.tag(
                "STP4216_EVENT_ROUTE",
                f"event=OnlineStatusEvent sender={sender!r} "
                f"expectedFacilityRecipient={self.facilities.get('ONLINE_STATUS_EVENT', '?')}",
            )

        # Async Login EVENT (origin-sdk EventBody::Login) — not a Request/Response
        login_ev = re.search(
            r'<Login\b([^>]*)/?>|'
            r'<Login\b[^>]*>.*?</Login>|'
            r"IsLoggedIn=|"
            r"LoginReasonCode=",
            xml,
            re.I | re.S,
        )
        is_login_event = bool(
            re.search(r"<Event\b[^>]*>\s*<Login\b", xml, re.I | re.S)
            or (
                kind == "Event"
                and re.search(r"\bIsLoggedIn=", xml, re.I)
                and re.search(r"<Login\b", xml, re.I)
            )
        )
        if is_login_event or (
            login_ev and kind == "Event" and "Challenge" not in btype and "IsLoggedIn" in xml
        ):
            self.saw_login_event = True
            self.login_event_sender = sender
            fields = {
                "IsLoggedIn": attr(xml, "IsLoggedIn"),
                "UserIndex": attr(xml, "UserIndex"),
                "LoginReasonCode": attr(xml, "LoginReasonCode"),
                "sender": sender,
                "id": mid,
            }
            self.login_event_fields = {k: v for k, v in fields.items() if v}
            self.tag(
                "STP4216_LOGIN_EVENT_SEEN",
                " ".join(f"{k}={v!r}" for k, v in self.login_event_fields.items())
                + f" xml={json.dumps(xml, ensure_ascii=False)}",
            )
            self.tag(
                "STP4216_LOGIN_EVENT_SENDER",
                f"sender={sender!r} expected=EbisuSDK "
                f"ok={int(sender.lower() == 'ebisusdk') if sender else 0}",
            )
            self.tag("STP4216_LOGIN_EVENT", common)
            self.tag(
                "STP_LOGIN_EVENT",
                " ".join(f"{k}={v!r}" for k, v in self.login_event_fields.items()),
            )

        if re.search(r"LoginEvent|LOGIN_EVENT", xml, re.I) and not is_login_event:
            self.tag("STP4216_LOGIN_EVENT", "mention " + common)

        if btype in ("GetProfile", "GetProfileResponse") or "GetProfileResponse" in xml:
            fields = {k: attr(xml, k) for k in PROFILE_FIELDS}
            # PersonaName fallback
            if not fields.get("Persona"):
                fields["Persona"] = attr(xml, "PersonaName")
            present = {k: v for k, v in fields.items() if v}
            missing = [k for k in PROFILE_FIELDS if not fields.get(k)]
            if present:
                self.profile_fields.update(present)
                for k in ("UserId", "PersonaId", "Persona"):
                    if fields.get(k):
                        self.identity[k] = fields[k]
            self.tag(
                "STP4216_PROFILE",
                f"present={len(present)}/{len(PROFILE_FIELDS)} missing={missing!r} "
                f"fields={present!r} xml={json.dumps(xml, ensure_ascii=False)}",
            )
            self.tag(
                "STP4216_PROFILE_RESPONSE",
                f"UserId={fields.get('UserId')} PersonaId={fields.get('PersonaId')} "
                f"Persona={fields.get('Persona')} missing={missing!r}",
            )

        if btype in ("GetAuthCode", "AuthCode", "GetAuthToken", "AuthToken"):
            code = attr(xml, "AuthCode") or attr(xml, "authCode") or attr(xml, "AuthToken")
            if code:
                self.authcode_value = code
            uid = attr(xml, "UserId")
            if uid:
                self.identity.setdefault("UserId", uid)
            self.tag(
                "STP4216_AUTHCODE",
                f"bodyType={btype} AuthCode={code!r} UserId={uid!r} "
                f"xml={json.dumps(xml, ensure_ascii=False)}",
            )
            self.tag(
                "STP4216_AUTHCODE_RESPONSE",
                f"AuthCode={code!r} UserId={uid!r} xml={json.dumps(xml, ensure_ascii=False)}",
            )

        if btype == "PostWincodes" or "PostWincodes" in xml:
            self.postwincodes_seen = True
            self.tag(
                "STP4216_POSTWINCODES",
                f"kind={kind} AuthCode={attr(xml,'AuthCode')!r} "
                f"UserId={attr(xml,'UserId')!r} PersonaId={attr(xml,'PersonaId')!r} "
                f"xml={json.dumps(xml, ensure_ascii=False)}",
            )

        if btype == "CurrentUserPresenceEvent" or "CurrentUserPresenceEvent" in xml:
            fields = {k: attr(xml, k) for k in PRESENCE_FIELDS}
            present = {k: v for k, v in fields.items() if v}
            self.presence_fields.update(present)
            mp = fields.get("MultiplayerId") or ""
            title = fields.get("Title") or ""
            mp_ok = (
                not mp
                or not self.identity.get("MultiplayerId")
                or mp == self.identity.get("MultiplayerId")
            )
            title_ok = (
                not title
                or not self.identity.get("Title")
                or title == self.identity.get("Title")
            )
            self.tag(
                "STP4216_PRESENCE_EVENT",
                f"fields={present!r} multiplayerMatch={int(mp_ok)} titleMatch={int(title_ok)} "
                f"challengeMp={self.identity.get('MultiplayerId')!r} "
                f"challengeTitle={self.identity.get('Title')!r} "
                f"xml={json.dumps(xml, ensure_ascii=False)}",
            )

    def flush(self) -> None:
        chrono = " → ".join(self.messages[:50])
        verdict = "NEED_MORE_DATA"
        why: list[str] = []

        # --- PROTOCOL_AUDIT gate (before login chain) ---
        proto = (self.sdk_protocol_version or "").strip()
        key_modes = self.decrypt_key_modes
        used_default = key_modes.get("default", 0) + key_modes.get(
            "session_fallback_default", 0
        )
        used_session = key_modes.get("session", 0)
        protocol_hard = False

        if not self.messages:
            verdict = "NO_MESSAGES"
            why.append("no LSX messages")
            protocol_hard = True
        elif not proto:
            why.append("ChallengeResponse @version not extracted (do not assume 3)")
        elif proto != "3":
            why.append(f"protocolVersion={proto!r} (!=3) — default key 00..0f may apply")
            if used_session and not used_default and self.decrypt_fail > self.decrypt_ok:
                verdict = "PROTOCOL_NON3_SESSION_KEY_MAY_BE_WRONG"
                why.append(f"keyModes={key_modes!r}")
                protocol_hard = True
        if (
            not protocol_hard
            and self.decrypt_fail > 0
            and self.decrypt_ok == 0
            and self.tracker.ready
        ):
            verdict = "DECRYPT_TOTAL_FAIL"
            why.append(f"keyModes={key_modes!r} protocolVersion={proto!r}")
            protocol_hard = True
        if used_default and used_session:
            why.append(f"mixedKeyModes={key_modes!r}")

        # Login / online chain unless hard protocol fail
        mo = (self.manual_offline or "").strip().lower()
        conn = (self.online_connected or "").strip().lower()
        is_on = (self.online_event_is_online or "").strip().lower()

        if not protocol_hard:
            chain_verdict = None
            if self.login_as_response:
                chain_verdict = "LOGIN_WRONG_ENVELOPE_RESPONSE"
                why.append("Login body inside <Response> — must be <Event>")
            elif mo in ("true", "1", "yes"):
                chain_verdict = "MANUAL_OFFLINE_TRUE"
                why.append(f"IsManualOffline={self.manual_offline!r}")
            elif self.manual_offline is None and any(
                x in self.messages
                for x in ("GetSettings", "GetSetting", "GetSettingsResponse")
            ):
                chain_verdict = "MANUAL_OFFLINE_UNPARSED"
                why.append("GetSettings seen but IsManualOffline not extracted")
            elif conn in ("0", "false"):
                chain_verdict = "CONNECTED_FALSE"
                why.append(f"InternetConnectedState connected={self.online_connected!r}")
            elif self.facilities and "LOGIN_EVENT" not in self.facilities:
                chain_verdict = "CONFIG_MISSING_LOGIN_EVENT"
                why.append(f"facilities={self.facilities!r}")
            elif conn in ("1", "true") and self.goonline_seen and self.goonline_code in (
                "0",
                "1",
                None,
            ):
                if not self.saw_online_event:
                    chain_verdict = "GOONLINE_OK_NO_ONLINE_STATUS_EVENT"
                    why.append(
                        f"connected=1 GoOnline Code={self.goonline_code!r} "
                        f"but no OnlineStatusEvent"
                    )
                elif is_on not in ("true", "1"):
                    chain_verdict = "ONLINE_EVENT_NOT_TRUE"
                    why.append(
                        f"OnlineStatusEvent isOnline={self.online_event_is_online!r}"
                    )
                elif not self.saw_login_event:
                    chain_verdict = "ONLINE_BUT_NO_LOGIN_EVENT"
                    why.append("isOnline=true but no Event/Login IsLoggedIn")
                    self.tag(
                        "STP4216_LOGIN_EVENT_MISSING",
                        "OnlineStatusEvent ok but Login Event absent",
                    )
                elif (
                    self.login_event_sender
                    and self.login_event_sender.lower() != "ebisusdk"
                ):
                    chain_verdict = "LOGIN_EVENT_WRONG_SENDER"
                    why.append(
                        f"sender={self.login_event_sender!r} expected EbisuSDK"
                    )
                elif self.login_complete_enter:
                    chain_verdict = "LOGIN_EVENT_AND_COMPLETE"
                    why.append("full chain + LoginComplete ENTER")
                elif self.txt_not_login:
                    chain_verdict = "LOGIN_EVENT_BUT_TXT_NOT_LOGIN"
                    why.append("Login Event seen but TXT_NOT_LOGIN_TO_EBISU remains")
                elif self.login_leaves:
                    chain_verdict = "LOGIN_EVENT_SEEN_CHECK_OUTFLAGS"
                    why.append("Login Event on wire — out-flags/Complete still pending")
                else:
                    chain_verdict = "LOGIN_EVENT_SEEN"
                    why.append(f"fields={self.login_event_fields!r}")
            elif conn in ("1", "true") and not self.goonline_seen:
                if not self.saw_login_event:
                    chain_verdict = "CONNECTED_NO_GOONLINE_NO_LOGIN"
                    why.append("connected=1 but no GoOnline and no Login Event")
                else:
                    chain_verdict = "LOGIN_WITHOUT_GOONLINE_PATH"
                    why.append("Login Event without GoOnline in transcript")
            elif not self.saw_login_event:
                if self.facilities.get("LOGIN_EVENT"):
                    chain_verdict = "LOGIN_EVENT_FACILITY_BUT_NEVER_EMITTED"
                    why.append(f"LOGIN_EVENT→{self.facilities.get('LOGIN_EVENT')}")
                else:
                    chain_verdict = "LOGIN_EVENT_MISSING"
                    why.append("no async Event/Login")
                self.tag(
                    "STP4216_LOGIN_EVENT_MISSING",
                    f"facilities={self.facilities!r} connected={self.online_connected!r} "
                    f"manualOffline={self.manual_offline!r}",
                )
            else:
                chain_verdict = "PARTIAL_CHAIN"
                why.append(
                    f"manual={self.manual_offline!r} connected={conn!r} "
                    f"goOnline={self.goonline_code!r} onlineEvt={is_on!r} "
                    f"loginEvt={self.saw_login_event}"
                )
            if chain_verdict:
                verdict = chain_verdict

        # CONNECTED_ONLY rewrite axis (Test 1)
        if (
            self.rewrite_match
            or self.rewrite_sent
            or os.environ.get("STP_OBS_MODE", "").upper() == "CONNECTED_ONLY"
            or os.environ.get("STP_OBS_MODE", "").upper().startswith("LSX_RESTORE")
        ):
            rw_verdict = "REWRITE_NO_MATCH"
            rw_why: list[str] = []
            if self.rewrite_sent and self.rewrite_verify_ok:
                rw_why.append("frame sent with connected=1")
                if self.origin_check_online_val in ("1", "0x1"):
                    rw_verdict = "CONNECTED1_ORIGIN_CHECK_1"
                    rw_why.append(f"ORIGIN_CHECK_ONLINE={self.origin_check_online_val}")
                elif self.origin_check_online_val in ("0", "0x0"):
                    rw_verdict = "CONNECTED1_BUT_ORIGIN_CHECK_0"
                    rw_why.append(
                        f"ORIGIN_CHECK_ONLINE={self.origin_check_online_val} — GetConfig next"
                    )
                elif self.saw_login_event:
                    rw_verdict = "CONNECTED1_LOGIN_SEEN"
                    rw_why.append("Login Event after rewrite")
                elif self.goonline_seen or self.saw_online_event:
                    rw_verdict = "CONNECTED1_ONLINE_CHAIN_STARTED"
                    rw_why.append(
                        f"GoOnline={self.goonline_seen} OnlineEvt={self.saw_online_event}"
                    )
                elif self.txt_not_login:
                    rw_verdict = "CONNECTED1_STILL_TXT_NOT_LOGIN"
                    rw_why.append("connected=1 but TXT_NOT_LOGIN remains")
                else:
                    rw_verdict = "CONNECTED1_SENT_WATCH_SEQUENCE"
                    rw_why.append("rewrite ok — watch GoOnline/OnlineStatus/Login")
            elif self.rewrite_match and not self.rewrite_sent:
                rw_verdict = "REWRITE_MATCH_BUT_NOT_SENT"
                rw_why.append("matched XML but send write failed")
            else:
                rw_verdict = "REWRITE_NO_MATCH"
                rw_why.append("no InternetConnectedState connected=0 seen/rewritten")
            self.tag(
                "STP_REWRITE_VERDICT",
                f"verdict={rw_verdict} why={';'.join(rw_why)!r} "
                f"match={self.rewrite_match} sent={self.rewrite_sent} "
                f"verifyOk={int(self.rewrite_verify_ok)} "
                f"wireConnected={self.online_connected!r} "
                f"originCheckOnline={self.origin_check_online_val!r} "
                f"goOnline={int(self.goonline_seen)} onlineEvt={int(self.saw_online_event)} "
                f"loginEvt={int(self.saw_login_event)} txtNotLogin={int(self.txt_not_login)}",
            )
            if os.environ.get("STP_OBS_MODE", "").upper() == "CONNECTED_ONLY":
                verdict = rw_verdict

        # GETCONFIG_MAP Test 2 verdict (primary = non-empty recipient)
        mode_u = os.environ.get("STP_OBS_MODE", "").upper()
        if (
            self.config_rewrite_match
            or self.config_rewrite_sent
            or mode_u in ("GETCONFIG_MAP", "CONFIG_MAP")
            or mode_u.startswith("COMBINED")
            or mode_u.startswith("LSX_RESTORE")
        ):
            cfg_verdict = "CONFIG_REWRITE_NO_MATCH"
            cfg_why: list[str] = []
            if self.config_rewrite_sent and self.config_rewrite_verify:
                cfg_why.append("GetConfig map frame sent+verified")
                if self.nonempty_recipient_after_config > 0:
                    cfg_verdict = "CONFIG_MAP_RECIPIENT_NONEMPTY"
                    cfg_why.append(
                        f"nonempty={self.nonempty_recipient_after_config} "
                        f"empty={self.empty_recipient_after_config}"
                    )
                    if self.goonline_seen:
                        cfg_verdict = "CONFIG_MAP_GOONLINE_SEEN"
                        cfg_why.append("GoOnline appeared naturally")
                    elif self.saw_online_event or self.saw_login_event:
                        cfg_verdict = "CONFIG_MAP_ONLINE_CHAIN"
                        cfg_why.append(
                            f"onlineEvt={self.saw_online_event} loginEvt={self.saw_login_event}"
                        )
                elif self.empty_recipient_after_config > 0 or any(
                    True for _ in self.messages
                ):
                    # requests after config still empty
                    post = [
                        m
                        for m in self.messages
                        if m
                        not in (
                            "Challenge",
                            "ChallengeResponse",
                            "ChallengeAccepted",
                            "GetConfig",
                            "GetConfigResponse",
                        )
                    ]
                    if post and self.nonempty_recipient_after_config == 0:
                        cfg_verdict = "CONFIG_MAP_BUT_RECIPIENT_EMPTY"
                        cfg_why.append(
                            "map received but later Request recipient still empty — schema?"
                        )
                    else:
                        cfg_verdict = "CONFIG_MAP_SENT_WATCH_RECIPIENT"
                        cfg_why.append("watch subsequent Request recipient")
                else:
                    cfg_verdict = "CONFIG_MAP_SENT_WATCH_RECIPIENT"
                    cfg_why.append("no post-config requests yet")
            elif self.config_rewrite_match and not self.config_rewrite_sent:
                cfg_verdict = "CONFIG_REWRITE_MATCH_NOT_SENT"
                cfg_why.append("matched but enlarge-send failed")
            else:
                cfg_why.append("no GetConfigResponse rewrite")
            self.tag(
                "STP_CONFIG_SEQUENCE",
                f"recipients={self.recipients_after_config[:20]!r} "
                f"goOnline={int(self.goonline_seen)} onlineEvt={int(self.saw_online_event)} "
                f"loginEvt={int(self.saw_login_event)} connected={self.online_connected!r}",
            )
            self.tag(
                "STP_CONFIG_VERDICT",
                f"verdict={cfg_verdict} why={';'.join(cfg_why)!r} "
                f"match={self.config_rewrite_match} sent={self.config_rewrite_sent} "
                f"verifyOk={int(self.config_rewrite_verify)} "
                f"configTrue={int(self.saw_config_true)} "
                f"nonemptyRecipient={self.nonempty_recipient_after_config} "
                f"emptyRecipient={self.empty_recipient_after_config} "
                f"facilities={self.facilities!r} "
                f"connectedRewriteSent={self.rewrite_sent} "
                f"wireConnected={self.online_connected!r} "
                f"goOnline={int(self.goonline_seen)} "
                f"NOTE=absence_of_GoOnline_alone_not_failure_under_CAS_B",
            )
            if mode_u in ("GETCONFIG_MAP", "CONFIG_MAP"):
                verdict = cfg_verdict

        # COMBINED_RESTORE_BLAZE_CONNECT_10041 — primary axe = connect :10041
        if mode_u.startswith("COMBINED"):
            comb_verdict = "COMBINED_CAS_B_NO_CONNECT_10041"
            comb_why: list[str] = []
            lsx_ok = (
                self.rewrite_sent
                and self.rewrite_verify_ok
                and self.config_rewrite_sent
                and self.config_rewrite_verify
            )
            comb_why.append(
                f"lsx_frozen connected1={int(bool(self.rewrite_sent and self.rewrite_verify_ok))} "
                f"configMap={int(bool(self.config_rewrite_sent and self.config_rewrite_verify))} "
                f"nonemptyRecipient={self.nonempty_recipient_after_config}"
            )
            if self.blaze_connect_seen or self.blaze_cas == "A":
                comb_verdict = "COMBINED_CAS_A_CONNECT_10041"
                comb_why.append("FIFA connect/WSAConnect :10041 seen")
                if self.goonline_seen:
                    comb_verdict = "COMBINED_BLAZE_THEN_GOONLINE"
                    comb_why.append("GoOnline after Blaze connect")
                elif self.saw_login_event:
                    comb_verdict = "COMBINED_BLAZE_THEN_LOGIN_EVENT"
                    comb_why.append("Login Event after Blaze connect")
                elif self.saw_online_event:
                    comb_verdict = "COMBINED_BLAZE_THEN_ONLINE_EVENT"
                    comb_why.append("OnlineStatusEvent after Blaze connect")
                else:
                    comb_why.append(
                        "NOTE=do_not_conclude_LSX_until_PreAuth_Auth_seen_on_server"
                    )
            elif self.blaze_cas == "B":
                comb_verdict = "COMBINED_CAS_B_NO_CONNECT_10041"
                comb_why.append("redirector reply without connect :10041")
            else:
                comb_verdict = "COMBINED_WAIT_REDIRECTOR_OR_CONNECT"
                comb_why.append("no CAS A/B verdict yet from ssl-bypass")
            if not lsx_ok:
                comb_why.append("WARN=LSX rewrite incomplete (connected/config)")
            self.tag(
                "STP_COMBINED_SEQUENCE",
                f"connected1={int(bool(self.online_connected in ('1', 'true')))} "
                f"configMap={int(bool(self.config_rewrite_verify))} "
                f"blazeCas={self.blaze_cas!r} blazeConnect={int(self.blaze_connect_seen)} "
                f"goOnline={int(self.goonline_seen)} onlineEvt={int(self.saw_online_event)} "
                f"loginEvt={int(self.saw_login_event)}",
            )
            self.tag(
                "STP_COMBINED_VERDICT",
                f"verdict={comb_verdict} why={';'.join(comb_why)!r} "
                f"cas={self.blaze_cas!r} blazeConnect={int(self.blaze_connect_seen)} "
                f"redirCommit={self.redir_commit_verdict!r} "
                f"resolveCb={int(self.resolve_cb_seen)} "
                f"primary=restore_connect_10041 "
                f"secondary_lsx=only_after_blaze_preauth_auth",
            )
            if self.redir_commit_verdict:
                self.tag(
                    "REDIR_COMMIT_VERDICT",
                    f"verdict={self.redir_commit_verdict} "
                    f"blazeConnect={int(self.blaze_connect_seen)} "
                    f"resolveCb={int(self.resolve_cb_seen)}",
                )
            # FORCE_ADDR causal final (upgrade if connect restored)
            if (
                self.force_addr_applied
                or self.force_addr_causal_verdict
                or os.environ.get("PIPE_FORCE_ADDR", "0").strip()
                in ("1", "true", "True", "yes")
            ):
                fc = self.force_addr_causal_verdict or "FORCE_ADDR_PENDING"
                if self.force_addr_applied and self.force_addr_verified:
                    if self.blaze_connect_seen or self.blaze_cas == "A":
                        fc = "FORCE_ADDR_RESTORES_CONNECT"
                    elif fc in (
                        "FORCE_ADDR_SET_WATCH_CONNECT",
                        "FORCE_ADDR_PENDING",
                        None,
                    ):
                        fc = "FORCE_ADDR_SET_BUT_NO_CONNECT_YET"
                self.tag(
                    "FORCE_ADDR_CAUSAL_VERDICT",
                    f"verdict={fc} applied={int(self.force_addr_applied)} "
                    f"verified={int(self.force_addr_verified)} "
                    f"blazeConnect={int(self.blaze_connect_seen)} "
                    f"cas={self.blaze_cas!r} resolveCb={int(self.resolve_cb_seen)}",
                )
                if fc == "FORCE_ADDR_RESTORES_CONNECT":
                    comb_verdict = "COMBINED_FORCE_ADDR_RESTORES_CONNECT"
                    verdict = comb_verdict
            verdict = comb_verdict

        # LSX_RESTORE / LSX_ORIGIN_ONLINE_BRIDGE
        mode_lsx = os.environ.get("STP_OBS_MODE", "").upper()
        if mode_lsx.startswith("LSX_RESTORE") or mode_lsx.startswith("LSX_ORIGIN"):
            lsx_why: list[str] = []
            origin_fix_on = os.environ.get("PIPE_ORIGIN_ONLINE_FIX", "0").strip() in (
                "1",
                "true",
                "True",
                "yes",
            )
            version_fix_on = os.environ.get(
                "PIPE_ORIGIN_VERSION_FIX", "0"
            ).strip() in ("1", "true", "True", "yes")
            path_obs_on = (
                os.environ.get("PIPE_AUTHSETUP_OBS", "0").strip()
                in ("1", "true", "True", "yes")
                or os.environ.get("PIPE_ORIGIN_VERSION_TOKEN_XREF_OBS", "0").strip()
                in ("1", "true", "True", "yes")
                or os.environ.get("PIPE_AUTH_CALLSITE_OBS", "0").strip()
                in ("1", "true", "True", "yes")
                or os.environ.get("PIPE_VERSION_TEXT_OBS", "0").strip()
                in ("1", "true", "True", "yes")
                or os.environ.get("PIPE_VERSION_STALKER_OBS", "0").strip()
                in ("1", "true", "True", "yes")
                or os.environ.get("PIPE_UI_HANDOFF_OBS", "0").strip()
                in ("1", "true", "True", "yes")
                or os.environ.get("PIPE_JOB_PAYLOAD_OBS", "0").strip()
                in ("1", "true", "True", "yes")
                or os.environ.get("PIPE_JOB_DISPATCH_OBS", "0").strip()
                in ("1", "true", "True", "yes")
            )
            if not self.session_key_seen:
                lsx_v = self.handshake_stage_verdict()
                lsx_why.append(
                    f"pre-SESSION_KEY stage lastStage={self.hs_last_stage} "
                    f"dll={self.hs_dll_loaded} bind={self.hs_bind_4216} "
                    f"listen={self.hs_listen_4216} connect={self.hs_client_connect} "
                    f"accept={self.hs_accept} challenge={self.hs_challenge} "
                    f"challengeResponse={self.hs_challenge_response} "
                    f"accepted={self.hs_challenge_accepted} "
                    f"socketClosed={self.hs_socket_closed} closeSide={self.hs_close_side} "
                    f"lastWsaError={self.hs_last_wsa_error}"
                )
                if self.hs_summary_line:
                    lsx_why.append(self.hs_summary_line[:240])
            elif (
                os.environ.get("PIPE_LSX_PROFILE8_BARRIER", "0").strip()
                in ("1", "true", "True", "yes")
                and self.arm_profile8 > 0
                and self.profile8_request_count == 0
                and "GetProfile#1" not in self.profile8_fifa_order
                and self.profile8_barrier_armed == 0
            ):
                lsx_v = "LSX_POST_HANDSHAKE_ARM_CRASH"
                lsx_why.append(
                    "SESSION_KEY+ARM_PROFILE8 but no GetProfile#1 "
                    f"(FIFA likely died post-handshake) "
                    f"decryptOk={self.decrypt_ok} armObsSkipped={self.arm_obs_skipped}"
                )
                self.tag(
                    "LSX_PROFILE8_SUMMARY",
                    f"handshakeVerdict=LSX_HANDSHAKE_OK "
                    f"profile8RequestCount=0 profile8UniqueHashes=0 "
                    f"profile8ResponseHeld=0 setPresence9Seen=0 "
                    f"profile8ResponseReleased=0 barrierTimeout=0 "
                    f"requestOrder=[] responseOrder=[] lastRequestId=- "
                    f"getInternetConnectedStateSeen=0 "
                    f"connectedRewriteSent=0 originOnlineFixApplied=0 "
                    f"finalVerdict={lsx_v}",
                )
            elif self.decrypt_ok == 0:
                lsx_v = "LSX_DECRYPT_FAIL"
                lsx_why.append(
                    f"key seen but decryptOk=0 fail={self.decrypt_fail} modes={key_modes!r}"
                )
            elif os.environ.get("PIPE_LSX_PROFILE8_BARRIER", "0").strip() in (
                "1",
                "true",
                "True",
                "yes",
            ) or self.profile8_barrier_armed:
                # Active barrier experiment only (timeline alone is NOT causal proof)
                order = self.profile8_fifa_order
                held_ok = self.profile8_response_held > 0
                released_ok = self.profile8_response_released > 0
                causal_gate = held_ok and released_ok
                valid_order = False
                try:
                    i1 = order.index("GetProfile#1")
                    isp = order.index("SetPresence#9")
                    i2 = order.index("GetProfile#2")
                    valid_order = i1 < isp < i2
                except ValueError:
                    valid_order = False
                stuck_at_10 = (
                    "Request#10" in order
                    and self.get_internet_connected_seen == 0
                    and not any(re.match(r"Request#(1[1-6])$", x) for x in order)
                )
                progressed_past_10 = any(
                    re.match(r"Request#(1[1-6])$", x) for x in order
                )
                if (
                    causal_gate
                    and self.get_internet_connected_seen > 0
                ):
                    lsx_v = "LSX_PROFILE8_ORDER_CAUSAL_CONFIRMED"
                    lsx_why.append(
                        f"HELD+RELEASED+GIC validOrder={int(valid_order)} "
                        f"order={order!r} bySock={self.profile8_order_by_sock!r}"
                    )
                elif self.get_internet_connected_seen > 0 and not causal_gate:
                    lsx_v = "LSX_BRIDGE_SUCCEEDED_WITHOUT_PROFILE8_BARRIER"
                    lsx_why.append(
                        "GIC/bridge without experimental hold "
                        f"held={self.profile8_response_held} "
                        f"released={self.profile8_response_released} "
                        f"order={order!r} — SetPresence-between-GetProfiles NOT necessary"
                    )
                elif (
                    self.profile8_barrier_timeout > 0
                    and self.setpresence9_seen == 0
                ):
                    lsx_v = "LSX_SETPRESENCE_DEPENDS_ON_PROFILE8_RESPONSE"
                    lsx_why.append(
                        "SetPresence id=9 not seen before 150ms barrier timeout"
                    )
                elif (
                    released_ok
                    and self.setpresence9_seen > 0
                    and self.get_internet_connected_seen == 0
                    and (stuck_at_10 or not progressed_past_10)
                ):
                    lsx_v = "LSX_PROFILE8_ORDER_NOT_SUFFICIENT"
                    lsx_why.append(
                        f"SetPresence released but no GIC; lastRequestId="
                        f"{self.profile8_last_request_id} order={order!r}"
                    )
                elif valid_order and self.get_internet_connected_seen == 0:
                    lsx_v = "LSX_PROFILE8_ORDER_NOT_SUFFICIENT"
                    lsx_why.append(
                        f"order restored but no GIC; order={order!r}"
                    )
                elif not causal_gate:
                    lsx_v = "LSX_PROFILE8_ORDER_NOT_CAUSAL"
                    lsx_why.append(
                        f"barrier armed but HELD/RELEASED incomplete "
                        f"held={self.profile8_response_held} "
                        f"released={self.profile8_response_released} "
                        f"order={order!r}"
                    )
                else:
                    lsx_v = "LSX_PROFILE8_ORDER_WATCH"
                    lsx_why.append(f"order={order!r} timeline={self.lsx_timeline}")
                self.tag(
                    "LSX_PROFILE8_SUMMARY",
                    f"handshakeVerdict="
                    f"{'LSX_HANDSHAKE_OK' if self.session_key_seen else self.handshake_stage_verdict()} "
                    f"profile8RequestCount={self.profile8_request_count} "
                    f"profile8UniqueHashes={self.profile8_unique_req} "
                    f"profile8ResponseHeld={self.profile8_response_held} "
                    f"setPresence9Seen={self.setpresence9_seen} "
                    f"profile8ResponseReleased={self.profile8_response_released} "
                    f"barrierTimeout={self.profile8_barrier_timeout} "
                    f"requestOrder={order!r} "
                    f"requestOrderBySock={self.profile8_order_by_sock!r} "
                    f"responseOrder={self.profile8_response_order!r} "
                    f"lastRequestId={self.profile8_last_request_id} "
                    f"idBodyTypeMismatch={self.lsx_id_bodytype_mismatch} "
                    f"getInternetConnectedStateSeen={self.get_internet_connected_seen} "
                    f"connectedRewriteSent={int(self.connected_rewrite_sent or bool(self.rewrite_sent))} "
                    f"originOnlineFixApplied={self.origin_online_fix_applied} "
                    f"finalVerdict={lsx_v}",
                )
            elif origin_fix_on and self.origin_online_fix_applied == 0:
                if path_obs_on:
                    lsx_v = "RUN_INVALID_NO_ORIGIN_EPOCH"
                    lsx_why.append(
                        "no ORIGIN_ONLINE_FIX_APPLIED — secondary/job signals from this run "
                        "must not count; need DECRYPT_OK→connectedRewrite→OriginCheck→fix"
                    )
                    lsx_why.append(
                        f"connectedRewriteSent={1 if self.connected_rewrite_sent else 0} "
                        f"originCheckEnter={self.origin_check_enter} "
                        f"decryptOk={self.decrypt_ok}"
                    )
                else:
                    lsx_v = "LSX_ORIGIN_FIX_NOT_APPLIED"
                    lsx_why.append("ORIGIN_ONLINE_FIX=1 but no applied tag")
            elif self.origin_check_online_val in ("1", "0x1") or (
                origin_fix_on and self.origin_online_fix_applied > 0
            ):
                lsx_v = "LSX_ORIGIN_CHECK_1"
                if self.origin_online_fix_applied:
                    lsx_why.append(
                        f"ORIGIN_ONLINE_FIX applied n={self.origin_online_fix_applied} "
                        f"retWas={self.origin_online_fix_ret_was!r}"
                    )
                else:
                    lsx_why.append("connected=1 path → OriginCheckOnline online=1")
                if version_fix_on and self.origin_version_fix_applied:
                    lsx_why.append(
                        f"ORIGIN_VERSION_FIX applied n={self.origin_version_fix_applied}"
                    )
                elif version_fix_on and self.origin_version_gate_hits == 0:
                    lsx_v = "LSX_VERSION_GATE_MISS"
                    lsx_why.append(
                        f"VERSION_FIX=1 but no ORIGIN_VERSION_GATE HIT "
                        f"authSetupEax={self.origin_auth_setup_eax!r}"
                    )
                elif version_fix_on and self.origin_version_fix_applied == 0:
                    lsx_v = "LSX_VERSION_GATE_NO_FIX"
                    lsx_why.append(
                        f"VERSION_GATE hits={self.origin_version_gate_hits} "
                        f"but no applied (ret!=0xa2000003?)"
                    )
                if self.get_authcode_seen:
                    lsx_v = "LSX_GET_AUTHCODE_SEEN"
                    lsx_why.append("GetAuthCode/GetAuthToken natural")
                if self.goonline_seen or self.goonline_tag_seen:
                    lsx_v = "LSX_GOONLINE_SEEN"
                    lsx_why.append("GoOnline natural")
                if self.saw_online_event or self.online_event_tag_seen:
                    lsx_v = "LSX_ONLINE_EVENT_SEEN"
                if self.saw_login_event or self.login_event_tag_seen:
                    lsx_v = "LSX_LOGIN_EVENT_SEEN"
                if self.blaze_auth10_seen:
                    lsx_v = "LSX_AUTH10_SEEN"
                    lsx_why.append("Auth/10 — Origin online+version unlocked")
                elif (
                    version_fix_on
                    and self.origin_version_fix_applied
                    and not self.get_authcode_seen
                    and not self.blaze_auth10_seen
                    and lsx_v
                    not in (
                        "LSX_VERSION_GATE_MISS",
                        "LSX_VERSION_GATE_NO_FIX",
                    )
                ):
                    lsx_v = "LSX_VERSION_FIX_NO_AUTHCODE"
                    lsx_why.append(
                        "VERSION_FIX applied but no GetAuthCode/Auth/10 — third gate?"
                    )
                elif (
                    origin_fix_on
                    and self.origin_online_fix_applied
                    and not version_fix_on
                    and not self.get_authcode_seen
                    and not self.blaze_auth10_seen
                ):
                    if path_obs_on:
                        # v11 second-stage FIFA reentry — only after valid Origin epoch
                        origin_epoch_ok = (
                            self.origin_online_fix_applied > 0
                            and self.origin_epoch_active > 0
                        )
                        if origin_epoch_ok and self.second_stage_target_enter > 0:
                            lsx_v = "LSX_ORIGIN_SECOND_STAGE_TARGET_IDENTIFIED"
                            lsx_why.append(
                                f"stageTargets={self.second_stage_target_enter} "
                                f"reentry={self.second_stage_reentry} "
                                f"dispatch={self.second_stage_dispatch_enter} "
                                f"vmethodDisp={self.second_stage_vmethod_dispatch} "
                                f"jobCand={self.second_stage_job_candidate}"
                            )
                        elif origin_epoch_ok and self.second_stage_dispatch_enter > 0:
                            lsx_v = "LSX_ORIGIN_SECOND_STAGE_DISPATCH_IDENTIFIED"
                            lsx_why.append(
                                f"dispatchEnter={self.second_stage_dispatch_enter} "
                                f"reentry={self.second_stage_reentry} "
                                f"vmethodDisp={self.second_stage_vmethod_dispatch} "
                                f"jobCand={self.second_stage_job_candidate} "
                                f"indirect={self.second_stage_indirect_call}"
                            )
                        elif origin_epoch_ok and self.second_stage_reentry > 0:
                            if self.second_stage_target_enter == 0:
                                lsx_v = "LSX_ORIGIN_SECOND_STAGE_REENTRY_NO_TARGET"
                                lsx_why.append(
                                    f"reentry={self.second_stage_reentry} "
                                    f"transfers={self.second_stage_control_transfer} "
                                    f"jobCand={self.second_stage_job_candidate} "
                                    "no SECOND_STAGE_TARGET_ENTER"
                                )
                            else:
                                lsx_v = "LSX_ORIGIN_SECOND_STAGE_REENTRY_CONFIRMED"
                                lsx_why.append(
                                    f"reentry={self.second_stage_reentry} "
                                    f"targets={self.second_stage_target_enter}"
                                )
                        elif (
                            origin_epoch_ok
                            and self.second_stage_oneshot_armed > 0
                            and self.second_stage_reentry == 0
                            and (
                                self.second_reentry_hook_miss > 0
                                or self.origin_second_wait_wake > 0
                            )
                        ):
                            lsx_v = "LSX_ORIGIN_SECOND_REENTRY_HOOK_MISS"
                            lsx_why.append(
                                f"oneshotArmed={self.second_stage_oneshot_armed} "
                                f"hookMiss={self.second_reentry_hook_miss} "
                                f"secondWake={self.origin_second_wait_wake} "
                                "oneshot never hit — instrumentation/returnAddress issue"
                            )
                        elif (
                            origin_epoch_ok
                            and (
                                self.second_sync_handoff_confirmed > 0
                                or self.origin_second_wait_wake > 0
                            )
                            and self.second_stage_reentry == 0
                            and self.second_stage_target_enter == 0
                            and self.second_stage_oneshot_armed == 0
                        ):
                            lsx_v = "LSX_ORIGIN_SECOND_WAKE_NO_TARGET"
                            lsx_why.append(
                                f"secondWake={self.origin_second_wait_wake} "
                                f"syncConfirmed={self.second_sync_handoff_confirmed} "
                                "no oneshot armed (waitReturnAddress validation failed?)"
                            )
                        elif (
                            origin_epoch_ok
                            and self.origin_callback_sync_secondary > 0
                            and self.origin_second_wait_wake == 0
                        ):
                            lsx_v = "LSX_ORIGIN_SECONDARY_SIGNAL_NO_WAITER"
                            lsx_why.append(
                                f"secondarySignals={self.origin_callback_sync_secondary} "
                                f"secondWaitEnter={self.origin_second_wait_enter} "
                                "no ORIGIN_SECOND_WAIT_WAKE"
                            )
                        elif (
                            origin_epoch_ok
                            and self.origin_job_target_identified
                            and self.origin_callback_sync > 0
                            and self.origin_callback_sync_secondary == 0
                            and self.origin_second_wait_wake == 0
                        ):
                            lsx_v = "LSX_ORIGIN_SCHEDULER_FANOUT_ONLY"
                            lsx_why.append(
                                f"targetOk sync={self.origin_callback_sync} "
                                "all handles classified pool/no secondary"
                            )
                        elif self.second_stage_ui:
                            lsx_v = "LSX_ORIGIN_UI_THREAD_HANDOFF_CONFIRMED"
                            lsx_why.append(f"secondStageUi={self.second_stage_ui}")
                        elif self.second_stage_lsx:
                            lsx_v = "LSX_ORIGIN_LSX_STAGE_IDENTIFIED"
                            lsx_why.append(f"secondStageLsx={self.second_stage_lsx}")
                        elif self.origin_payload_enter or self.origin_job_payload_enter:
                            lsx_v = "LSX_ORIGIN_PAYLOAD_TARGET_IDENTIFIED"
                            lsx_why.append(
                                f"payloadEnter={self.origin_payload_enter or self.origin_job_payload_enter}"
                            )
                        elif (
                            self.origin_job_target_identified
                            or (
                                self.origin_job_vmethod_enter
                                and self.seq1_vmethod_rcx_match
                            )
                        ):
                            lsx_v = "LSX_ORIGIN_JOB_TARGET_IDENTIFIED"
                            lsx_why.append(
                                f"target={self.origin_identified_target or self.seq1_identified_target!r} "
                                f"enter={self.origin_job_vmethod_enter} "
                                f"rcxMatch={self.seq1_vmethod_rcx_match} "
                                f"sync={self.origin_callback_sync} "
                                f"secondarySync={self.origin_callback_sync_secondary}"
                            )
                        elif self.origin_callback_ui:
                            lsx_v = "LSX_ORIGIN_UI_HANDOFF_CONFIRMED"
                            lsx_why.append(f"originCallbackUi={self.origin_callback_ui}")
                        elif self.origin_callback_async:
                            lsx_v = "LSX_ORIGIN_ASYNC_CALLBACK_IDENTIFIED"
                            lsx_why.append(
                                f"originCallbackAsync={self.origin_callback_async}"
                            )
                        elif (
                            self.origin_online_fix_applied
                            and self.origin_epoch_active
                            and self.origin_job_node_candidate
                            and not self.origin_job_vmethod_enter
                        ):
                            lsx_v = "LSX_ORIGIN_JOB_NODE_CANDIDATE_PENDING"
                            lsx_why.append(
                                f"nodeCandidate={self.origin_job_node_candidate} "
                                f"vmethodHooked={self.seq1_vmethod_hooked} "
                                "awaiting RCX=originJobNode enter"
                            )
                        elif (
                            self.origin_online_fix_applied
                            and self.origin_epoch_active
                            and not self.origin_job_node_candidate
                        ):
                            lsx_v = "LSX_ORIGIN_EPOCH_NO_JOB_YET"
                            lsx_why.append(
                                f"epochActive bootSkipped={self.boot_job_skipped} "
                                "await first post-bridge enqueue"
                            )
                        elif self.job_vmethod_dispatch_confirmed:
                            lsx_v = "LSX_JOB_VMETHOD_DISPATCH_CONFIRMED"
                            lsx_why.append(
                                "pool convention known; awaiting valid Origin epoch chain"
                            )
                        elif self.seq1_target_with_node:
                            lsx_v = "LSX_ORIGIN_JOB_TARGET_IDENTIFIED"
                            lsx_why.append(
                                f"target={self.seq1_identified_target!r} "
                                f"nodeTargets={self.seq1_target_with_node} "
                                f"transfers={self.seq1_control_transfer}"
                            )
                        elif self.seq1_tailcall_with_node:
                            lsx_v = "LSX_ORIGIN_JOB_TAILCALL_IDENTIFIED"
                            lsx_why.append(
                                f"target={self.seq1_identified_target!r} "
                                f"tailcalls={self.seq1_tailcall_with_node}"
                            )
                        elif (
                            self.seq1_vmethod_hooked
                            and self.job_seq1_wake
                            and not self.seq1_vmethod_enter
                        ):
                            lsx_v = "LSX_ORIGIN_JOB_VMETHOD_CANDIDATE"
                            lsx_why.append(
                                f"hooked={self.seq1_vmethod_target!r} "
                                "armedAtCapture but no causal enter yet"
                            )
                        elif (
                            self.seq1_vmethod_generic
                            and not self.seq1_vmethod_enter
                            and self.seq1_vmethod_hooked
                        ):
                            lsx_v = "LSX_ORIGIN_JOB_VMETHOD_FALSE_CANDIDATE"
                            lsx_why.append(
                                f"genericEnter={self.seq1_vmethod_generic} "
                                "no jobNode in args"
                            )
                        elif (
                            self.job_dispatch_enter
                            and self.job_seq1_wake
                            and self.seq1_control_transfer
                            and not self.seq1_target_with_node
                        ):
                            lsx_v = "LSX_ORIGIN_JOB_NODE_CONTEXT_ONLY"
                            lsx_why.append(
                                f"dispatch+transfers={self.seq1_control_transfer} "
                                "but no jobNode in target args "
                                "(r9 may be context, not dispatch node)"
                            )
                        elif (
                            self.job_callback_enter
                            and (
                                self.job_callback_rcx_match
                                or self.job_callback_wake_tid_match
                                or self.job_ctx_match
                            )
                            and self.job_seq1_wake
                        ):
                            lsx_v = "LSX_ORIGIN_JOB_CALLBACK_CONFIRMED"
                            lsx_why.append(
                                f"callbackEnter={self.job_callback_enter} "
                                f"rcxMatch={self.job_callback_rcx_match} "
                                f"wakeTidMatch={self.job_callback_wake_tid_match} "
                                f"ctxMatch={self.job_ctx_match}"
                            )
                        elif (
                            self.job_dispatch_enter
                            and self.job_seq1_wake
                            and not self.job_callback_enter
                            and self.job_callback_target
                            and "5380960" not in (self.job_callback_target or "")
                        ):
                            lsx_v = "LSX_ORIGIN_JOB_CALLBACK_REPLACED"
                            lsx_why.append(
                                f"seq1 dispatch ok; first calls target="
                                f"{self.job_callback_target!r} (not 0x5380960)"
                            )
                        elif self.job_dispatch_enter and self.job_seq1_wake and not self.job_callback_enter:
                            lsx_v = "LSX_POOL_CALLBACK_IDENTIFIED"
                            lsx_why.append(
                                "seq1→dispatch confirmed; pool callback not causal"
                            )
                        elif (
                            self.job_callback_dispatch
                            and self.job_callback_target
                            and "5380960" not in (self.job_callback_target or "")
                            and self.job_seq1_wake
                        ):
                            lsx_v = "LSX_ORIGIN_JOB_CALLBACK_REPLACED"
                            lsx_why.append(
                                f"target={self.job_callback_target!r} "
                                f"(not 0x5380960 on causal dispatch)"
                            )
                        elif self.callback_ui:
                            lsx_v = "LSX_UI_THREAD_HANDOFF_CONFIRMED"
                            lsx_why.append(f"uiHandoff n={self.callback_ui}")
                        elif self.callback_sync:
                            lsx_v = "LSX_SECOND_SYNC_HANDOFF"
                            lsx_why.append(f"sync n={self.callback_sync}")
                        elif self.callback_global_write:
                            lsx_v = "LSX_UI_STATE_WRITE_IDENTIFIED"
                            lsx_why.append(
                                f"globalWrites={self.callback_global_write}"
                            )
                        elif self.job_callback_enter and self.job_seq1_wake:
                            lsx_v = "LSX_POOL_CALLBACK_IDENTIFIED"
                            lsx_why.append(
                                "callback entered in window but no seq1 ctx match"
                            )
                        elif self.job_indirect:
                            tgt = (self.job_indirect_target or "").lower()
                            if "user32" in tgt or "dialog" in tgt or "messagebox" in tgt:
                                lsx_v = "LSX_VERSION_UI_PATH_IDENTIFIED"
                            else:
                                lsx_v = "LSX_POOL_CALLBACK_IDENTIFIED"
                            lsx_why.append(
                                f"indirect={self.job_indirect} "
                                f"target={self.job_indirect_target!r} "
                                f"enqueue={self.job_enqueue} wake={self.job_wake}"
                            )
                        elif self.job_enqueue and self.job_wake:
                            lsx_v = "LSX_JOB_PAYLOAD_IDENTIFIED"
                            lsx_why.append(
                                f"enqueue={self.job_enqueue} wake={self.job_wake} "
                                "(same-handle correlation; no indirect yet)"
                            )
                        elif self.job_enqueue and not self.job_wake:
                            lsx_v = "LSX_JOB_ENQUEUE_NO_WAKE"
                            lsx_why.append(
                                "enqueue seen but no correlated worker wake"
                            )
                        elif self.ui_handoff_msg:
                            lsx_v = "LSX_UI_MESSAGE_HANDOFF"
                            lsx_why.append(
                                f"Post/SendMessage n={self.ui_handoff_msg} "
                                f"windowTid={self.fifa_window_tid!r}"
                            )
                        elif self.async_callback_enter or self.ui_handoff_async:
                            lsx_v = "LSX_ASYNC_CALLBACK_HANDOFF"
                            lsx_why.append(
                                f"queued={self.ui_handoff_async} "
                                f"enter={self.async_callback_enter}"
                            )
                        elif self.ui_handoff_sync:
                            lsx_v = "LSX_SYNC_SIGNAL_HANDOFF"
                            lsx_why.append(f"sync n={self.ui_handoff_sync}")
                        elif self.version_scan_credible and (
                            self.version_text_reads or self.version_text_writes
                        ):
                            lsx_v = (
                                "LSX_VERSION_TEXT_WRITER"
                                if self.version_text_writes
                                else "LSX_VERSION_TEXT_READER"
                            )
                            lsx_why.append(
                                f"credible text access r={self.version_text_reads} "
                                f"w={self.version_text_writes}"
                            )
                        elif self.ui_stalker_start and self.version_scan_credible:
                            lsx_v = "LSX_UI_THREAD_TEXT_FOUND"
                            lsx_why.append(
                                f"UI stalker + credible text "
                                f"windowTid={self.fifa_window_tid!r}"
                            )
                        elif self.ui_stalker_start:
                            lsx_v = "LSX_UI_THREAD_ACTIVE_NO_TEXT"
                            lsx_why.append(
                                f"windowTid={self.fifa_window_tid!r} stalker ok, "
                                "no credible FR text yet"
                            )
                        elif self.origin_check_enter == 0:
                            lsx_v = "LSX_ORIGIN_CHECK_MISS"
                            lsx_why.append("OriginCheckOnline ENTER never seen")
                        else:
                            lsx_v = "LSX_VERSION_UI_HANDOFF_NOT_CAPTURED"
                            lsx_why.append(
                                f"originTid={self.origin_check_tid!r} "
                                f"windowTid={self.fifa_window_tid!r} "
                                "no PostMessage/APC/SetEvent handoff from originTid"
                            )
                    else:
                        lsx_v = "LSX_ORIGIN_FIX_NO_AUTHCODE"
                        lsx_why.append(
                            "OriginCheck forced online=1 but no GetAuthCode/Auth/10 yet — second gate?"
                        )
            elif (self.rewrite_sent or self.connected_rewrite_sent) and self.origin_check_online_val in (
                "0",
                "0x0",
            ):
                lsx_v = "LSX_CONNECTED1_BUT_ORIGIN_CHECK_0"
                lsx_why.append(
                    f"wireConnected={self.online_connected!r} "
                    f"originCheck={self.origin_check_online_val!r}"
                )
            elif self.decrypt_ok > 0 and not self.rewrite_sent and not self.config_rewrite_sent:
                lsx_v = "LSX_DECRYPT_OK_NO_REWRITE"
                lsx_why.append("DECRYPT_OK but no GetConfig/connected rewrite")
            else:
                lsx_v = self.lsx_restore_verdict or "LSX_DECRYPT_OK_WATCH"
                lsx_why.append(
                    f"decryptOk={self.decrypt_ok} rewriteSent={self.rewrite_sent} "
                    f"configSent={self.config_rewrite_sent} "
                    f"originCheck={self.origin_check_online_val!r} "
                    f"connected={self.online_connected!r}"
                )
            # Passive PROFILE8 timeline documentation (barrier OFF) — never claims causal
            barrier_exp = os.environ.get("PIPE_LSX_PROFILE8_BARRIER", "0").strip() in (
                "1",
                "true",
                "True",
                "yes",
            ) or self.profile8_barrier_armed
            if self.lsx_timeline and not barrier_exp:
                if (
                    self.get_internet_connected_seen > 0
                    and self.profile8_response_held == 0
                ):
                    p8_doc = "LSX_BRIDGE_SUCCEEDED_WITHOUT_PROFILE8_BARRIER"
                else:
                    p8_doc = "LSX_PROFILE8_ORDER_NOT_CAUSAL"
                self.tag(
                    "LSX_PROFILE8_SUMMARY",
                    f"handshakeVerdict="
                    f"{'LSX_HANDSHAKE_OK' if self.session_key_seen else self.handshake_stage_verdict()} "
                    f"profile8RequestCount={self.profile8_request_count} "
                    f"profile8UniqueHashes={self.profile8_unique_req} "
                    f"profile8ResponseHeld={self.profile8_response_held} "
                    f"setPresence9Seen={self.setpresence9_seen} "
                    f"profile8ResponseReleased={self.profile8_response_released} "
                    f"barrierTimeout={self.profile8_barrier_timeout} "
                    f"requestOrder={self.profile8_fifa_order!r} "
                    f"requestOrderBySock={self.profile8_order_by_sock!r} "
                    f"responseOrder={self.profile8_response_order!r} "
                    f"lastRequestId={self.profile8_last_request_id} "
                    f"idBodyTypeMismatch={self.lsx_id_bodytype_mismatch} "
                    f"getInternetConnectedStateSeen={self.get_internet_connected_seen} "
                    f"connectedRewriteSent={int(self.connected_rewrite_sent or bool(self.rewrite_sent))} "
                    f"originOnlineFixApplied={self.origin_online_fix_applied} "
                    f"observeOnly=1 finalVerdict={p8_doc}",
                )
                lsx_why.append(f"profile8PassiveDoc={p8_doc}")
            self.tag(
                "LSX_RESTORE_VERDICT",
                f"verdict={lsx_v} why={';'.join(lsx_why)!r} "
                f"dllLoaded={self.hs_dll_loaded} "
                f"bind4216={self.hs_bind_4216} "
                f"listen4216={self.hs_listen_4216} "
                f"clientConnect={self.hs_client_connect} "
                f"accept={self.hs_accept} "
                f"challenge={self.hs_challenge} "
                f"challengeResponse={self.hs_challenge_response} "
                f"challengeAccepted={int(self.challenge_accepted_seen or self.hs_challenge_accepted)} "
                f"sessionKey={int(self.session_key_seen or self.hs_session_key)} "
                f"socketClosed={self.hs_socket_closed} "
                f"closeSide={self.hs_close_side} "
                f"lastWsaError={self.hs_last_wsa_error} "
                f"lastStage={self.hs_last_stage} "
                f"finalVerdict={lsx_v} "
                f"armProfile8={self.arm_profile8} "
                f"armOriginBridge={self.arm_origin_bridge} "
                f"armObsV11={self.arm_obs_v11} "
                f"handshakeCaptured={int(self.handshake_captured)} "
                f"decryptOk={self.decrypt_ok} decryptFail={self.decrypt_fail} "
                f"connectedRewriteSent={int(self.connected_rewrite_sent or bool(self.rewrite_sent))} "
                f"connectedRewriteVerify={int(self.connected_rewrite_verify or self.rewrite_verify_ok)} "
                f"getInternetConnectedStateSeen={self.get_internet_connected_seen} "
                f"profile8Timeline={self.lsx_timeline} "
                f"profile8UniqueReq={self.profile8_unique_req} "
                f"profile8HashDup={self.profile8_hash_dup} "
                f"profile8Order={self.profile8_fifa_order!r} "
                f"profile8BarrierArmed={self.profile8_barrier_armed} "
                f"profile8Held={self.profile8_response_held} "
                f"setPresence9={self.setpresence9_seen} "
                f"profile8Released={self.profile8_response_released} "
                f"profile8Timeout={self.profile8_barrier_timeout} "
                f"configMapAccepted={int(self.config_rewrite_verify)} "
                f"wireConnected={self.online_connected!r} "
                f"originCheckOnline={self.origin_check_online_val!r} "
                f"originOnlineFix={self.origin_online_fix_applied} "
                f"originFixRetWas={self.origin_online_fix_ret_was!r} "
                f"originVersionGateHits={self.origin_version_gate_hits} "
                f"originVersionFix={self.origin_version_fix_applied} "
                f"authSetupEax={self.origin_auth_setup_eax!r} "
                f"authSetupEnter={self.authsetup_enter} "
                f"authSetupLeave={self.authsetup_leave} "
                f"authSetupRet={self.authsetup_leave_ret!r} "
                f"callsite717d68d={self.auth_callsite_717d68d_hits} "
                f"originCheckEnter={self.origin_check_enter} "
                f"originCheckLeaveObs={self.origin_check_leave_obs} "
                f"originTid={self.origin_check_tid!r} "
                f"fifaWindowTid={self.fifa_window_tid!r} "
                f"stalkerOriginStart={self.stalker_origin_start} "
                f"stalkerUiStart={self.ui_stalker_start} "
                f"uiMsgHandoff={self.ui_handoff_msg} "
                f"uiAsyncHandoff={self.ui_handoff_async} "
                f"uiSyncHandoff={self.ui_handoff_sync} "
                f"jobEnqueue={self.job_enqueue} "
                f"jobWake={self.job_wake} "
                f"jobSeq1Enqueue={self.job_seq1_enqueue} "
                f"jobSeq1Wake={self.job_seq1_wake} "
                f"jobDispatch={self.job_dispatch_enter} "
                f"originEpoch={self.origin_epoch_active} "
                f"originJobCandidate={self.origin_job_node_candidate} "
                f"originVmethodEnter={self.origin_job_vmethod_enter} "
                f"originTargetId={self.origin_job_target_identified} "
                f"bootJobSkipped={self.boot_job_skipped} "
                f"jobVmethodDispatchConfirmed={self.job_vmethod_dispatch_confirmed} "
                f"originCallbackSync={self.origin_callback_sync} "
                f"originCallbackSyncSecondary={self.origin_callback_sync_secondary} "
                f"originSecondaryHandle={self.origin_secondary_handle} "
                f"originSecondWaitEnter={self.origin_second_wait_enter} "
                f"originSecondWaitWake={self.origin_second_wait_wake} "
                f"originSecondSyncId={self.origin_second_sync_identified} "
                f"secondStageTargetEnter={self.second_stage_target_enter} "
                f"secondStageReentry={self.second_stage_reentry} "
                f"secondStageDispatch={self.second_stage_dispatch_enter} "
                f"secondStageVmethodDisp={self.second_stage_vmethod_dispatch} "
                f"secondStageJobCand={self.second_stage_job_candidate} "
                f"secondStageIndirect={self.second_stage_indirect_call} "
                f"secondSyncConfirmed={self.second_sync_handoff_confirmed} "
                f"secondStageOneshotArmed={self.second_stage_oneshot_armed} "
                f"secondReentryHookMiss={self.second_reentry_hook_miss} "
                f"secondStageUi={self.second_stage_ui} "
                f"secondStageSync={self.second_stage_sync} "
                f"originPayloadEnter={self.origin_payload_enter} "
                f"originCallbackUi={self.origin_callback_ui} "
                f"originCallbackAsync={self.origin_callback_async} "
                f"seq1NodeCapture={self.seq1_node_capture} "
                f"seq1VmethodHooked={self.seq1_vmethod_hooked} "
                f"seq1VmethodEnter={self.seq1_vmethod_enter} "
                f"seq1VmethodRcxMatch={self.seq1_vmethod_rcx_match} "
                f"seq1VmethodGeneric={self.seq1_vmethod_generic} "
                f"seq1VmethodLeave={self.seq1_vmethod_leave} "
                f"seq1PayloadEnter={self.seq1_payload_target_enter} "
                f"seq1Transfers={self.seq1_control_transfer} "
                f"seq1TargetEnter={self.seq1_target_enter} "
                f"seq1TargetWithNode={self.seq1_target_with_node} "
                f"seq1TailcallNode={self.seq1_tailcall_with_node} "
                f"seq1IdentifiedTarget={self.seq1_identified_target!r} "
                f"seq1CallbackSync={self.seq1_callback_sync} "
                f"seq1CallbackUi={self.seq1_callback_ui} "
                f"seq1CallbackAsync={self.seq1_callback_async} "
                f"seq1Sync={self.seq1_sync} "
                f"seq1Ui={self.seq1_ui} "
                f"seq1Async={self.seq1_async} "
                f"seq1GlobalWrite={self.seq1_global_write} "
                f"jobCbDispatch={self.job_callback_dispatch} "
                f"jobCbEnter={self.job_callback_enter} "
                f"jobCbRcxMatch={self.job_callback_rcx_match} "
                f"jobCbWakeTidMatch={self.job_callback_wake_tid_match} "
                f"jobCtxMatch={self.job_ctx_match} "
                f"cbSync={self.callback_sync} "
                f"cbUi={self.callback_ui} "
                f"cbAsync={self.callback_async} "
                f"cbGlobalWrite={self.callback_global_write} "
                f"jobIndirect={self.job_indirect} "
                f"jobIndirectTarget={self.job_indirect_target!r} "
                f"asyncCbEnter={self.async_callback_enter} "
                f"versionTextFound={self.version_text_found} "
                f"versionTextCredible={self.version_scan_credible} "
                f"versionTextReads={self.version_text_reads} "
                f"versionTextWrites={self.version_text_writes} "
                f"versionErrImm={self.version_error_imm} "
                f"versionErrRet={self.version_error_ret} "
                f"versionTokenXref={self.version_token_xref_hits} "
                f"localizeToken={int(self.localize_token_seen)} "
                f"popupDispatch={int(self.popup_dispatch_seen)} "
                f"getAuthCode={int(self.get_authcode_seen)} "
                f"goOnline={int(self.goonline_seen or self.goonline_tag_seen)} "
                f"onlineEvent={int(self.saw_online_event or self.online_event_tag_seen)} "
                f"loginEvent={int(self.saw_login_event or self.login_event_tag_seen)} "
                f"blazeAuth10={int(self.blaze_auth10_seen)} "
                f"forceAddrConnect={int(self.blaze_connect_seen)}",
            )
            verdict = lsx_v

        profile_missing = [k for k in PROFILE_FIELDS if k not in self.profile_fields]
        self.tag(
            "STP4216_PROTOCOL_VERDICT",
            f"verdict={verdict} why={';'.join(why)!r} "
            f"protocolVersion={self.sdk_protocol_version!r} "
            f"sdkVersion={self.sdk_version!r} "
            f"decryptOk={self.decrypt_ok} decryptFail={self.decrypt_fail} "
            f"keyModes={key_modes!r} "
            f"idMatchOk={self.id_match_ok} idMatchFail={self.id_match_fail} "
            f"eventWithId={self.event_with_id} "
            f"loginAsResponse={int(self.login_as_response)} "
            f"IsManualOffline={self.manual_offline!r} "
            f"connected={self.online_connected!r} "
            f"GoOnlineCode={self.goonline_code!r} "
            f"isOnline={self.online_event_is_online!r} "
            f"loginEvent={int(self.saw_login_event)} "
            f"middlewareReason={self.middleware_reason!r} "
            f"postWincodes={int(self.postwincodes_seen)} "
            f"authCode={bool(self.authcode_value)} "
            f"profileFields={len(self.profile_fields)}/{len(PROFILE_FIELDS)} "
            f"profileMissing={profile_missing!r} "
            f"identity={self.identity!r} "
            f"facilities={self.facilities!r} "
            f"txtNotLogin={int(self.txt_not_login)} "
            f"loginComplete={int(self.login_complete_enter)} "
            f"chronology={chrono!r}",
        )
        self.tag(
            "STP4216_FINAL_VERDICT",
            f"verdict={verdict} why={';'.join(why)!r} "
            f"IsManualOffline={self.manual_offline!r} "
            f"connected={self.online_connected!r} "
            f"GoOnlineCode={self.goonline_code!r} "
            f"isOnline={self.online_event_is_online!r} "
            f"loginEvent={int(self.saw_login_event)} "
            f"loginSender={self.login_event_sender!r} "
            f"loginFields={self.login_event_fields!r} "
            f"protocolVersion={self.sdk_protocol_version!r} "
            f"sdkVersion={self.sdk_version!r} "
            f"txtNotLogin={int(self.txt_not_login)} "
            f"loginComplete={int(self.login_complete_enter)} "
            f"facilities={self.facilities!r} "
            f"chronology={chrono!r}",
        )
        self.tag(
            "STP4216_LOGIN_VERDICT",
            f"verdict={verdict} why={';'.join(why)!r} "
            f"loginEventSeen={int(self.saw_login_event)} "
            f"loginEventSender={self.login_event_sender!r} "
            f"loginFields={self.login_event_fields!r} "
            f"txtNotLogin={int(self.txt_not_login)} "
            f"loginComplete={int(self.login_complete_enter)} "
            f"connected={self.online_connected!r} "
            f"IsManualOffline={self.manual_offline!r} "
            f"isOnline={self.online_event_is_online!r} "
            f"GoOnlineCode={self.goonline_code!r}",
        )
        self.tag(
            "STP4216_CONTRACT_VERDICT",
            f"verdict={verdict} why={';'.join(why)!r} chronology={chrono!r}",
        )
        self.tag(
            "STP4216_VERDICT",
            f"decryptOk={self.decrypt_ok} decryptFail={self.decrypt_fail} "
            f"keyModes={key_modes!r} msgTypes={len(self.messages)} chronology={chrono!r}",
        )
        try:
            self.latest.write_text("\n".join(self.lines) + "\n", encoding="utf-8")
            chrono_path = self.latest.with_name(self.latest.stem + "-chrono.txt")
            chrono_path.write_text(
                "\n".join(f"{i+1}. {m}" for i, m in enumerate(self.messages)) + "\n",
                encoding="utf-8",
            )
            fac_path = self.latest.with_name(self.latest.stem + "-facilities.txt")
            fac_path.write_text(
                "\n".join(f"{k} → {v}" for k, v in sorted(self.facilities.items())) + "\n",
                encoding="utf-8",
            )
            summary = self.latest.with_name(self.latest.stem + "-v2-summary.txt")
            summary.write_text(
                "\n".join(
                    [
                        f"verdict={verdict}",
                        f"why={';'.join(why)}",
                        f"protocolVersion={self.sdk_protocol_version}",
                        f"sdkVersion={self.sdk_version}",
                        f"keyModes={key_modes}",
                        f"IsManualOffline={self.manual_offline}",
                        f"connected={self.online_connected}",
                        f"GoOnlineCode={self.goonline_code}",
                        f"isOnline={self.online_event_is_online}",
                        f"loginEvent={self.saw_login_event}",
                        f"loginSender={self.login_event_sender}",
                        f"loginFields={self.login_event_fields}",
                        f"middlewareReason={self.middleware_reason}",
                        f"postWincodes={self.postwincodes_seen}",
                        f"profileMissing={profile_missing}",
                        f"identity={self.identity}",
                        f"chronology={chrono}",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            audit = self.latest.with_name(self.latest.stem + "-protocol-audit.txt")
            audit.write_text(
                "\n".join(
                    [
                        "=== STP4216_PROTOCOL_AUDIT ===",
                        f"verdict={verdict}",
                        f"why={';'.join(why)}",
                        f"protocolVersion(@version)={self.sdk_protocol_version}",
                        f"sdkVersion(<Version>)={self.sdk_version}",
                        f"decryptOk={self.decrypt_ok} decryptFail={self.decrypt_fail}",
                        f"keyModes={key_modes}",
                        f"idMatchOk={self.id_match_ok} idMatchFail={self.id_match_fail}",
                        f"eventWithId={self.event_with_id} loginAsResponse={self.login_as_response}",
                        f"IsManualOffline={self.manual_offline}",
                        f"connected={self.online_connected}",
                        f"GoOnlineCode={self.goonline_code}",
                        f"isOnline={self.online_event_is_online}",
                        f"loginEvent={self.saw_login_event} fields={self.login_event_fields}",
                        f"middlewareReason={self.middleware_reason}",
                        f"postWincodes={self.postwincodes_seen}",
                        f"authCodeSeen={bool(self.authcode_value)}",
                        f"profile={self.profile_fields}",
                        f"profileMissing={profile_missing}",
                        f"presence={self.presence_fields}",
                        f"identity={self.identity}",
                        "--- Facility → Recipient ---",
                        *[f"{k} → {v}" for k, v in sorted(self.facilities.items())],
                        "--- Chronology ---",
                        *[f"{i+1}. {m}" for i, m in enumerate(self.messages)],
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
        except OSError:
            pass


def main() -> None:
    mode = os.environ.get("STP_OBS_MODE", "TRANSCRIPT").strip() or "TRANSCRIPT"
    spawn = os.environ.get("STP_OBS_SPAWN", "1").strip() in ("1", "true", "True", "yes")
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    log_path = LOG_DIR / f"t-{mode}-{stamp}.log"
    latest = LOG_DIR / f"latest-{mode}.log"
    sink = TranscriptSink(log_path, latest)

    dll = ROOT.parent / "FIFA 17" / "stp-origin_emu.dll"
    print("[stp4216] DLL SHA256 expected db7482962b3eefd80808fbcaf7ac405d190d0519ff14cd6487fa177be69a5b20")
    do_origin_online_fix = os.environ.get("PIPE_ORIGIN_ONLINE_FIX", "0").strip() in (
        "1",
        "true",
        "True",
        "yes",
    )
    do_profile8_barrier = os.environ.get("PIPE_LSX_PROFILE8_BARRIER", "0").strip() in (
        "1",
        "true",
        "True",
        "yes",
    )
    do_profile8_timeline = os.environ.get("PIPE_LSX_PROFILE8_TIMELINE", "1").strip() in (
        "1",
        "true",
        "True",
        "yes",
    )
    do_gic_precursor_obs = os.environ.get("PIPE_LSX_GIC_PRECURSOR_OBS", "0").strip() in (
        "1",
        "true",
        "True",
        "yes",
    )
    do_origin_version_fix_banner = os.environ.get(
        "PIPE_ORIGIN_VERSION_FIX", "0"
    ).strip() in ("1", "true", "True", "yes")
    print(f"[stp4216] DLL path={dll} exists={dll.is_file()}")
    print(f"[stp4216] script={SCRIPT_PATH.name}")
    print(f"[stp4216] log -> {log_path}")
    print(
        "[stp4216] NO SUCC_POKE / NO Login inject | "
        f"ORIGIN_ONLINE_FIX={int(do_origin_online_fix)} "
        f"ORIGIN_VERSION_FIX={int(do_origin_version_fix_banner)} "
        f"PROFILE8_BARRIER={int(do_profile8_barrier)} "
        f"PROFILE8_TIMELINE={int(do_profile8_timeline)}"
    )

    do_text_obs = os.environ.get("PIPE_VERSION_TEXT_OBS", "0").strip() in (
        "1",
        "true",
        "True",
        "yes",
    )
    do_stalker_obs = os.environ.get("PIPE_VERSION_STALKER_OBS", "0").strip() in (
        "1",
        "true",
        "True",
        "yes",
    )
    do_handoff_obs = os.environ.get("PIPE_UI_HANDOFF_OBS", "0").strip() in (
        "1",
        "true",
        "True",
        "yes",
    )
    do_job_payload_obs = os.environ.get("PIPE_JOB_PAYLOAD_OBS", "0").strip() in (
        "1",
        "true",
        "True",
        "yes",
    )
    do_job_dispatch_obs = os.environ.get("PIPE_JOB_DISPATCH_OBS", "0").strip() in (
        "1",
        "true",
        "True",
        "yes",
    )
    if os.environ.get("PIPE_AUTHSETUP_OBS", "0").strip() in (
        "1",
        "true",
        "True",
        "yes",
    ) or os.environ.get("PIPE_ORIGIN_VERSION_TOKEN_XREF_OBS", "0").strip() in (
        "1",
        "true",
        "True",
        "yes",
    ):
        do_text_obs = True
        do_handoff_obs = True

    device = frida.get_local_device()
    if spawn:
        exe = default_fifa_path()
        print(f"[stp4216] SPAWN {exe}")
        pid = device.spawn([str(exe)], cwd=str(exe.parent))
        session = device.attach(pid)
    else:
        pid = find_fifa_pid()
        print(f"[stp4216] attach pid={pid}")
        session = device.attach(pid)

    def _load_js(name: str, src: str, prefix: str = "[stp4216] "):
        sc = session.create_script(src)

        def on_message(message, data):  # noqa: ANN001
            if message.get("type") == "error":
                sink.out(prefix + "ERROR " + str(message))
            else:
                sink.out(str(message.get("payload", message)))

        def on_log(level, text):  # noqa: ANN001
            sink.out(text.rstrip("\n"))

        sc.on("message", on_message)
        try:
            sc.set_log_handler(on_log)
        except Exception:
            pass
        sc.load()
        print(f"{prefix}{name} armed")
        return sc

    # Strict dispatch OBS — deferred until ARM_OBS_V11 / SESSION_KEY (handshake-first)
    job_sc = None
    job_obs_loaded = {"n": 0}

    def load_job_obs_deferred(reason: str = "ARM_OBS_V11") -> None:
        nonlocal job_sc
        if job_obs_loaded["n"]:
            return
        if not do_job_dispatch_obs or not ORIGIN_JOB_DISPATCH_OBS.is_file():
            if do_job_payload_obs and ORIGIN_JOB_PAYLOAD_OBS.is_file() and not job_obs_loaded["n"]:
                job_obs_loaded["n"] = 1
                print(
                    f"[stp4216] loading origin-job-payload-obs AFTER {reason} "
                    "(deferred past :4216 handshake)"
                )
                try:
                    _load_js(
                        "origin-job-payload-obs",
                        ORIGIN_JOB_PAYLOAD_OBS.read_text(encoding="utf-8"),
                        "[job] ",
                    )
                except Exception as e:
                    print(f"[stp4216] origin-job-payload-obs load failed: {e}")
            return
        job_obs_loaded["n"] = 1
        print(
            f"[stp4216] loading origin-job-dispatch-obs AFTER {reason} "
            "(ORIGIN second-sync → FIFA +0x5e3195c reentry → target)"
        )
        try:
            job_sc = _load_js(
                "origin-job-dispatch-obs",
                ORIGIN_JOB_DISPATCH_OBS.read_text(encoding="utf-8"),
                "[job] ",
            )

            def _notify_origin_epoch(text: str) -> None:
                if not job_sc:
                    return
                job_sc.post(
                    {
                        "type": "origin-epoch",
                        "payload": text[:400],
                    }
                )
                sink.out("[job] ORIGIN_EPOCH_POSTED from=ORIGIN_ONLINE_FIX_APPLIED")

            sink.origin_epoch_notify = _notify_origin_epoch
        except Exception as e:
            print(f"[stp4216] origin-job-dispatch-obs load failed: {e}")

    sink._arm_obs_callback = lambda: load_job_obs_deferred("ARM_OBS_V11")

    if do_job_dispatch_obs or do_job_payload_obs:
        print(
            "[stp4216] OBS v11 / job-payload DEFERRED until ARM_OBS_V11 "
            "(after LSX_SESSION_KEY) — handshake hooks only for now"
        )
    else:
        print(
            "[stp4216] OBS v11 DISABLED for this run "
            "(PROFILE8 + Origin bridge only after SESSION_KEY)"
        )

    # Path OBS — skipped when job-* owns the axis (also deferred conceptually;
    # only load when job obs is off so it doesn't fight handshake)
    if (
        not do_job_payload_obs
        and not do_job_dispatch_obs
        and (do_text_obs or do_stalker_obs or do_handoff_obs)
        and ORIGIN_VERSION_PATH_OBS.is_file()
    ):
        print(
            "[stp4216] loading origin-version-path-obs "
            f"(HANDOFF={int(do_handoff_obs)} TEXT={int(do_text_obs)})"
        )
        obs_src = (
            f"var __DO_UI_HANDOFF_OBS__ = {str(do_handoff_obs).lower()};\n"
            f"var __DO_VERSION_TEXT_OBS__ = {str(do_text_obs).lower()};\n"
            f"var __DO_VERSION_STALKER_OBS__ = false;\n"
            + ORIGIN_VERSION_PATH_OBS.read_text(encoding="utf-8")
        )
        try:
            _load_js("origin-version-path-obs", obs_src, "[ver-path] ")
        except Exception as e:
            print(f"[stp4216] origin-version-path-obs load failed: {e}")

    src = (
        f"var STP_OBS_MODE = {mode!r};\n"
        f"var __DO_ORIGIN_ONLINE_FIX__ = {str(do_origin_online_fix).lower()};\n"
        f"var __DO_LSX_PROFILE8_BARRIER__ = {str(do_profile8_barrier).lower()};\n"
        f"var __DO_LSX_PROFILE8_TIMELINE__ = {str(do_profile8_timeline).lower()};\n"
        f"var __DO_LSX_GIC_PRECURSOR_OBS__ = {str(do_gic_precursor_obs).lower()};\n"
        f"var __DO_ARM_OBS_V11__ = {str(do_job_dispatch_obs).lower()};\n"
        + SCRIPT_PATH.read_text(encoding="utf-8")
    )
    script = _load_js("LSX rewrite (ws2)", src)
    print(
        "[stp4216] LSX rewrite armed (ws2) — handshake+PROFILE8 "
        f"ARM_OBS_V11={int(do_job_dispatch_obs)}"
    )
    defer_heavy = os.environ.get("STP_DEFER_HEAVY", "0").strip() in (
        "1",
        "true",
        "True",
        "yes",
    )

    def wait_lsx_handshake_or_window(timeout_s: float = 20.0) -> str:
        """Keep LSX-only until ChallengeAccepted/SESSION_KEY, or FIFA window, or timeout."""
        print(
            "[stp4216] DEFER_HEAVY=1 — waiting SESSION_KEY / ChallengeAccepted "
            f"(timeout={timeout_s:.0f}s) before ssl/redir"
        )
        t0 = time.time()
        while time.time() - t0 < timeout_s:
            if sink.session_key_seen or sink.challenge_accepted_seen:
                # Prefer ARM_OBS_V11 path; only schedule here if marker already missed
                if not job_obs_loaded["n"] and do_job_dispatch_obs:
                    import threading

                    threading.Timer(
                        0.15, lambda: load_job_obs_deferred("SESSION_KEY")
                    ).start()
                return "session_key"
            if sink.handshake_captured and sink.decrypt_ok > 0:
                if not job_obs_loaded["n"] and do_job_dispatch_obs:
                    import threading

                    threading.Timer(
                        0.15, lambda: load_job_obs_deferred("HANDSHAKE_DECRYPT")
                    ).start()
                return "decrypt_ok"
            # Cipher without key ⇒ handshake already over (attach still late)
            if sink.decrypt_fail >= 2 and not sink.session_key_seen and (time.time() - t0) >= 2.5:
                return "cipher_without_key"
            time.sleep(0.1)
        return "timeout"

    resume_attached = os.environ.get("STP_RESUME_ATTACHED", "0").strip() in (
        "1",
        "true",
        "True",
        "yes",
    )
    if spawn or resume_attached:
        device.resume(pid)
        resume_signal = os.environ.get("STP_RESUME_SIGNAL_FILE", "").strip()
        if resume_signal:
            try:
                Path(resume_signal).write_text(str(pid), encoding="ascii")
            except Exception as e:
                print(f"[stp4216] resume signal write failed: {e}")
        print(
            f"[stp4216] resumed pid={pid} after early LSX hooks "
            f"(spawn={int(spawn)} attached={int(resume_attached)})"
        )
        time.sleep(2.0)

    if defer_heavy:
        try:
            defer_s = float(os.environ.get("STP_DEFER_HEAVY_S", "90").strip() or "90")
        except ValueError:
            defer_s = 90.0
        defer_s = max(20.0, min(defer_s, 180.0))
        reason = wait_lsx_handshake_or_window(defer_s)
        print(f"[stp4216] heavy hooks gate reason={reason} "
              f"sessionKey={int(sink.session_key_seen)} "
              f"challengeAccepted={int(sink.challenge_accepted_seen)} "
              f"decryptOk={sink.decrypt_ok}")
        # Extra settle so FIFA.exe Interceptor sites are valid
        time.sleep(0.8)

    # Optional ProtoSSL bypass (all Origin/Login pokes remain 0)
    with_ssl = os.environ.get("STP_WITH_SSL", "1").strip() in ("1", "true", "True", "yes")
    ssl_script = None
    if with_ssl and SSL_PATH.is_file():
        print("[stp4216] loading ssl-bypass (Origin/Login pokes=0)")
        ssl_src = SSL_PATH.read_text(encoding="utf-8")
        # Causal/obs: SSL observes connect only. Destination write = redir FORCE_ADDR
        # (v114). Never INJECT_BLAZE_ADDR / FORCE_BLAZE hijack here.
        ssl_src = ssl_src.replace(
            "const INJECT_BLAZE_ADDR = true;",
            "const INJECT_BLAZE_ADDR = false;",
        )
        if os.environ.get("BLAZE_OBSERVE_ONLY", "0").strip() in (
            "1",
            "true",
            "True",
            "yes",
        ):
            ssl_src = ssl_src.replace(
                "const FORCE_BLAZE = true;",
                "const FORCE_BLAZE = false;",
            )
        try:
            ssl_script = session.create_script(ssl_src)
        except Exception as e:
            print(f"[stp4216] ssl-bypass load FAILED (non-fatal for LSX obs): {e}")
            ssl_script = None

        def on_ssl_log(level, text):  # noqa: ANN001
            if ssl_script is None:
                return
            line = text.rstrip("\n")
            verbose = os.environ.get("STP_SSL_VERBOSE", "0").strip() in (
                "1",
                "true",
                "True",
                "yes",
            ) or os.environ.get("STP_OBS_MODE", "").upper().startswith(
                ("COMBINED", "LSX_RESTORE")
            )
            keys = (
                "BLAZE_CONNECT",
                "BLAZE_CONNECT_ATTEMPT",
                "BLAZE_CONNECT_RESULT",
                "REDIRECTOR_REPLY",
                "REDIR_HANDLER",
                "CONNECT_RAW",
                "CONNECT_UNEXPECTED",
                "FORCE_BLAZE",
                "VERDICT",
                "SSL_BYPASS",
                "PROTO_SSL",
                "PreAuth",
                "AUTH",
                "NUCLEUS_CONNECT",
                "XML_BODY",
                "XML_FIELDS",
                "CAS ",
                "BLAZE_TLS",
                "BLAZE_CLIENTHELLO",
                "BLAZE_CKE",
                "BLAZE_APP",
                "BLAZE_RECV",
                "BLAZE_ALERT",
                "PARSE_INT",
                "ReferenceError",
                "ERROR",
            )
            if verbose or any(k in line for k in keys) or "error" in line.lower():
                sink.out_raw("[ssl] " + line)
                # Mirror structured tags into combined clock
                for tag_name in (
                    "REDIRECTOR_REPLY",
                    "REDIR_HANDLER_ENTER",
                    "REDIR_HANDLER_EXIT",
                    "BLAZE_CONNECT_ATTEMPT",
                    "BLAZE_CONNECT_RESULT",
                    "SSL_BYPASS_HIT",
                    "PROTO_SSL_STATE",
                    "BLAZE_TLS_ESTABLISHED",
                    "BLAZE_CLIENTHELLO",
                    "BLAZE_CKE",
                    "BLAZE_APP_OUT_FIRST",
                    "CONNECT_RAW",
                    "CONNECT_UNEXPECTED",
                    "PARSE_INT",
                ):
                    if tag_name in line:
                        sink.tag(tag_name, line.split(tag_name, 1)[-1].strip())
                if "★★★ BLAZE_CONNECT" in line or (
                    "BLAZE_CONNECT " in line and "ATTEMPT" not in line and "RESULT" not in line
                ):
                    sink.blaze_connect_seen = True
                    sink.tag("BLAZE_CONNECT", line)
                if "VERDICT CAS A" in line:
                    sink.blaze_cas = "A"
                    sink.tag("COMBINED_VERDICT", "cas=A blaze_connect_seen")
                if "VERDICT CAS B" in line:
                    sink.blaze_cas = "B"
                    sink.tag("COMBINED_VERDICT", "cas=B no_connect_10041")

        def on_ssl_msg(message, data):  # noqa: ANN001
            if message.get("type") == "error":
                sink.out_raw("[ssl] ERROR " + str(message))

        if ssl_script is not None:
            ssl_script.on("message", on_ssl_msg)
            try:
                ssl_script.set_log_handler(on_ssl_log)
            except Exception:
                pass
            try:
                ssl_script.load()
                print("[stp4216] ssl-bypass armed")
            except Exception as e:
                print(f"[stp4216] ssl-bypass load failed: {e}")
        else:
            print("[stp4216] ssl-bypass skipped — continuing LSX/obs without SSL script")

    # REDIRECTOR_RESULT_COMMIT — lean Fire2 resolve_cb obs (FORCE_ADDR=0)
    hook_xrefs = os.environ.get("HOOK_XREFS", "0").strip() in ("1", "true", "True", "yes")
    redir_script = None
    if hook_xrefs and REDIR_COMMIT_PATH.is_file():
        do_force_causal = os.environ.get("PIPE_FORCE_ADDR", "0").strip() in (
            "1",
            "true",
            "True",
            "yes",
        )
        do_fix_timer = os.environ.get("PIPE_FIX_TIMER", "0").strip() in (
            "1",
            "true",
            "True",
            "yes",
        )
        do_crash_fix = os.environ.get("PIPE_CRASH_FIX", "0").strip() in (
            "1",
            "true",
            "True",
            "yes",
        )
        do_resolver_clean = os.environ.get("PIPE_RESOLVER_CLEAN_FIX", "0").strip() in (
            "1",
            "true",
            "True",
            "yes",
        )
        print(
            "[stp4216] loading redir-commit-obs "
            f"(HOOK_XREFS lean, FORCE_ADDR_CAUSAL={int(do_force_causal)}, "
            f"FIX_TIMER={int(do_fix_timer)}, CRASH_FIX={int(do_crash_fix)}, "
            f"RESOLVER_CLEAN={int(do_resolver_clean)}, no Login/out-flags pokes)"
        )
        redir_src = (
            f"var __DO_FORCE_ADDR_CAUSAL__ = {str(do_force_causal).lower()};\n"
            f"var __DO_FIX_TIMER__ = {str(do_fix_timer).lower()};\n"
            f"var __DO_CRASH_FIX__ = {str(do_crash_fix).lower()};\n"
            f"var __DO_RESOLVER_CLEAN_FIX__ = {str(do_resolver_clean).lower()};\n"
            + REDIR_COMMIT_PATH.read_text(encoding="utf-8")
        )
        try:
            redir_script = session.create_script(redir_src)
        except Exception as e:
            print(f"[stp4216] redir-commit-obs create FAILED (non-fatal for LSX obs): {e}")
            redir_script = None

        if redir_script is not None:

            def on_redir_log(level, text):  # noqa: ANN001
                line = text.rstrip("\n")
                sink.out_raw("[redir] " + line)
                for tag_name in (
                    "RESOLVE_CB_ENTER",
                    "RESOLVE_CB_EXIT",
                    "REDIR_OUT_WRITE",
                    "POST_REDIR_CALL",
                    "POST_REDIR_BRANCH",
                    "POST_REDIR_STATE",
                    "POST_REDIR_ABORT",
                    "FIRST_DIVERGENT_BRANCH",
                    "REDIR_COMMIT_VERDICT",
                    "CAS_A_RESOLVE_CALLSITE",
                    "CAS_B_RESOLVE_CALLSITE",
                    "CAS_A_OUTPTR_LAYOUT",
                    "CAS_B_OUTPTR_LAYOUT",
                    "CAS_A_POST_RESOLVE_PATH",
                    "CAS_B_POST_RESOLVE_PATH",
                    "FORCE_ADDR_CAUSAL_MATCH",
                    "FORCE_ADDR_CAUSAL_APPLIED",
                    "FORCE_ADDR_CAUSAL_VERIFY",
                    "FORCE_ADDR_CAUSAL_VERDICT",
                    "POST_FORCE_VT4",
                    "POST_FORCE_VT8",
                    "POST_FORCE_CONNECT_INIT",
                    "FIX_TIMER",
                    "CRASH_SENTINEL_FIX",
                    "CRASH_SENTINEL_RDX_FIX",
                    "POST_PING_RESOLVER_CLEAN_FIX",
                ):
                    if tag_name in line:
                        payload = line.split(tag_name, 1)[-1].strip()
                        sink.tag(tag_name, payload)
                        if tag_name == "RESOLVE_CB_ENTER":
                            sink.resolve_cb_seen = True
                        if tag_name == "REDIR_COMMIT_VERDICT":
                            m = re.search(r"verdict=(\S+)", payload)
                            if m:
                                sink.redir_commit_verdict = m.group(1)
                        if tag_name == "FORCE_ADDR_CAUSAL_VERDICT":
                            m = re.search(r"verdict=(\S+)", payload)
                            if m:
                                sink.force_addr_causal_verdict = m.group(1)
                        if tag_name == "FORCE_ADDR_CAUSAL_APPLIED" and "FAIL" not in line:
                            sink.force_addr_applied = True
                        if tag_name == "FORCE_ADDR_CAUSAL_VERIFY" and "ok=1" in line:
                            sink.force_addr_verified = True

            def on_redir_msg(message, data):  # noqa: ANN001
                if message.get("type") == "error":
                    sink.out_raw("[redir] ERROR " + str(message))

            redir_script.on("message", on_redir_msg)
            try:
                redir_script.set_log_handler(on_redir_log)
            except Exception:
                pass
            try:
                redir_script.load()
                print("[stp4216] redir-commit-obs armed")
            except Exception as e:
                print(f"[stp4216] redir-commit-obs load failed: {e}")
    # ORIGIN_VERSION_FIX opt-in only (path-obs already loaded first above)
    do_version_fix = os.environ.get("PIPE_ORIGIN_VERSION_FIX", "0").strip() in (
        "1",
        "true",
        "True",
        "yes",
    )

    if do_version_fix and ORIGIN_VERSION_PATH.is_file():
        print(
            "[stp4216] loading origin-version-fix "
            "(ORIGIN_VERSION_GATE 0xa2000003→0 only)"
        )
        ver_src = (
            "var __DO_ORIGIN_VERSION_FIX__ = true;\n"
            + ORIGIN_VERSION_PATH.read_text(encoding="utf-8")
        )
        try:
            _load_js("origin-version-fix", ver_src, "[origin-ver] ")
        except Exception as e:
            print(f"[stp4216] origin-version-fix load failed: {e}")

    if spawn:
        print(f"[stp4216] spawn live pid={pid} — wait STP4216_PROTOCOL_VERDICT (~120s)")
    else:
        print(f"[stp4216] attached pid={pid} — wait LSX handshake / PROTOCOL_VERDICT")

    max_s = float(os.environ.get("STP_OBS_MAX_S", "0") or "0")
    t_end = time.time() + max_s if max_s > 0 else None
    if t_end:
        print(f"[stp4216] auto-stop after {max_s:.0f}s (STP_OBS_MAX_S)")

    try:
        while True:
            if t_end and time.time() >= t_end:
                print(f"[stp4216] STP_OBS_MAX_S reached — flushing verdict")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print("[stp4216] detach")
    finally:
        sink.flush()
        try:
            session.detach()
        except Exception:
            pass
        print(f"[stp4216] wrote {log_path}")
        print(f"[stp4216] latest -> {latest}")


if __name__ == "__main__":
    main()
