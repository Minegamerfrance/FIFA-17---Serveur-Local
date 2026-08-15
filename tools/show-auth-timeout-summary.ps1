param(
  [string]$LogPath,
  [int]$MaxLines = 220
)

$ErrorActionPreference = "Stop"

if (-not $LogPath) {
  $LogPath = Join-Path $PSScriptRoot "versions\v114-AUTH-PLST\frida.log"
}

if (-not (Test-Path -LiteralPath $LogPath)) {
  Write-Host "Log introuvable: $LogPath"
  exit 1
}

$pattern = "AUTH10_COMPLETE|AUTH10_LINK|AUTH10_VT30|JOB_BRIDGE|WRITE260|AUTH10_RPC_DISPATCH|AUTH10_PENDING|AUTH10_CALLBACK|JOB_COMPLETION|AUTH10_JOBSTASH|LOGIN_JOBQ_DEEP stash job1|STATUS_SLOT_POKE|STATUS_COMPLETE_POKE|STATUS_SLOT0_COMPLETE_POKE|STATUS_MGR_DUMP|WAITER5_THIS|WAITER5_HELPER|WAITER_SLOT5_RET_POKE|AUTH_WAITER_DONE_POKE|AUTH_JOBQ_DONE_POKE|POST_LOGIN_COMPLETION_POKES|LOGIN_RET_DONE_POKE|LOGIN_BUSY_WHY|LOGIN_STATE_SUCC_POKE|LOGIN_COMPLETE_CALL|LOGIN_COMPLETE_FIND|LOGIN_COMPLETE_STATUS_SCAN|LOGIN_COMPLETE_CHOOSE|AUTO_DETACH_AFTER_LOGIN|LOGIN_STATE_POKE|LOGIN_STATE_CASE|CNNS_READY_POKE|CNNS_READY_WRITERS|CNNS_VT20|OBS_SUCC260|WAITER_60_VERDICT|WAITER_60_ARMED|WAITER_60_WRITE|BEFORE_BUSY|INIT_BUSY|armedBefore2|BUSY_POLL LEAVE JobqHeaderGet|LOGIN_STATE Login left BUSY|AUTH_LEAN Authentication enqueue cmd=10|AUTH_LEAN Authentication enqueue cmd=70|AUTH_REPLY_PROFILE|REQ originAuthCodeLogin|REP originAuthCodeLogin|REQ logout|ORIGIN_UI_LEAN|LOGIN_CB_VT0|EBISU|ORIGIN_LEAN INTERNAL|ORIGIN_CHECK_ONLINE|ORIGIN_ONLINE_FIX applied|ORIGIN_AUTH_SETUP|ORIGIN_AUTHCODE|ORIGIN_VERSION_GATE|ORIGIN_VERSION_FIX applied|E8_SANITY|ORPHAN_SCAN|ORPHAN_WRITER_REGSTORE|ORPHAN_WRITER_SITE|ORPHAN_WRITER_HOOKS|ORPHAN_WRITER_SITE_ENTER|ORPHAN_WRITER_FN_ENTER|ORPHAN_WRITER_FN_ONLY|ORPHAN_FN_ONLY|ORPHAN_AUTH_SNAP|ORPHAN_LOGIN_SLOTS|ORPHAN_XREF|ORPHAN_STATIC_ONLY|ORPHAN_STATIC_LINK|ORPHAN_PRIMARY|ORPHAN_NO_STATIC|ORPHAN_NO_WRITER5|WRITER5_INSTANCE_CONFIRMED site=|WRITER5_OTHER_OBJECT|WRITER5_FLOW_GATE|WRITER5_VERDICT|SUCC6_BRANCH|SUCC6_ATTACH_FAIL|SUCC6_WINDOW_DISASM|SUCC6_JCC|SUCC6_CALL|SUCC6_STORE_ENTER|POST_PING_RESOLVER_CLEAN_FIX applied|POST_PING_RESOLVER_CLEAN_FIX refused|DETACH after APPLY lean skipped|CRASH_EXCEPTION #|CRASH_SENTINEL_FIX applied|CRASH_SENTINEL_RDX_FIX applied"

Write-Host "=== Log: $LogPath ==="
Write-Host "=== Compteurs utiles ==="

$countPatterns = @(
  "PIPE_ORPHAN_LISTENER=true",
  "PIPE_ORPHAN_STATIC_ONLY=true",
  "PIPE_ORPHAN_FN_ONLY=true",
  "E8_SANITY_GATE",
  "E8_SANITY_OK",
  "E8_SANITY_HOLD",
  "ORPHAN_XREF index ready",
  "ORPHAN_XREF_SANITY knownCall.*OK",
  "ORPHAN_SCAN",
  "ORPHAN_WRITER_REGSTORE",
  "ORPHAN_WRITER_SITE",
  "ORPHAN_WRITER_SITE imm=5",
  "ORPHAN_WRITER_SITE imm=6",
  "ORPHAN_WRITER_HOOKS",
  "ORPHAN_WRITER_SITE_ENTER",
  "ORPHAN_WRITER_FN_ENTER",
  "ORPHAN_WRITER_FN_ONLY",
  "ORPHAN_FN_ONLY",
  "ORPHAN_AUTH_SNAP",
  "ORPHAN_LOGIN_SLOTS",
  "ORPHAN_STATIC_ONLY",
  "ORPHAN_STATIC_LINK",
  "ORPHAN_PRIMARY",
  "ORPHAN_NO_STATIC",
  "ORPHAN_NO_WRITER5",
  "WRITER5_INSTANCE_CONFIRMED site=",
  "WRITER5_OTHER_OBJECT",
  "SUCC6_BRANCH",
  "SUCC6_ATTACH_FAIL",
  "SUCC6_JCC",
  "SUCC6_CALL",
  "SUCC6_STORE_ENTER",
  "POST_PING_RESOLVER_CLEAN_FIX applied",
  "POST_PING_RESOLVER_CLEAN_FIX refused",
  "DETACH after APPLY lean skipped",
  "CRASH_EXCEPTION #",
  "CRASH_EXCEPTION #.*illegal-instruction",
  "CRASH_EXCEPTION #.*rva=0x71b5c16",
  "CRASH_SENTINEL_FIX applied",
  "CRASH_SENTINEL_RDX_FIX applied",
  "ORIGIN_LEAN INTERNAL ENTER.*OriginCheckOnlineWrapper",
  "ORIGIN_CHECK_ONLINE OBS ret=0x0 online=0->0",
  "ORIGIN_ONLINE_FIX applied",
  "ORIGIN_AUTHCODE_ARGS ENTER",
  "ORIGIN_AUTHCODE_FIX applied",
  "ORIGIN_UI_LEAN ENTER",
  "ORIGIN_UI_LEAN LEAVE",
  "LOGIN_CB_VT0 ENTER",
  "LOGIN_CB_VT0_LEAVE",
  "EBISU_FIX cleared",
  "ORIGIN_AUTH_SETUP RESULT.*EARLY_ORIGIN_ERROR_PATH",
  "ORIGIN_VERSION_GATE hooked",
  "ORIGIN_VERSION_GATE HIT",
  "ORIGIN_VERSION_FIX applied",
  "AUTH10_RPC_DISPATCH Auth/10 REPLY seen",
  "AUTH10_CALLBACK_INVOKED",
  "AUTH10_COMPLETE_VERDICT",
  "PIPE_LOGIN_260_MAM=true",
  "PIPE_LOGIN_STATE_POKE=true",
  "PIPE_LOGIN_STATE_SUCC_POKE=true",
  "PIPE_LOGIN_COMPLETE_CALL=true",
  "PIPE_LOGIN_RET_DONE_POKE=true",
  "LOGIN_RET_DONE_POKE #",
  "PIPE_AUTO_DETACH_AFTER_LOGIN=true",
  "PIPE_AUTH_WAITER_DONE_POKE=true",
  "PIPE_AUTH_JOBQ_DONE_POKE=true",
  "PIPE_STATUS_COMPLETE_POKE=true",
  "PIPE_STATUS_SLOT0_COMPLETE_POKE=true",
  "AUTH_WAITER_DONE_POKE waiter\+0x60=2->3",
  "AUTH_WAITER_DONE_POKE skip",
  "AUTH_WAITER_DONE_POKE miss",
  "AUTH_JOBQ_DONE_POKE q\+0x8 active8=1->0",
  "AUTH_JOBQ_DONE_POKE skip",
  "AUTH_JOBQ_DONE_POKE miss",
  "AUTH_JOBQ_DONE_POKE FAIL",
  "POST_LOGIN_COMPLETION_POKES scheduled",
  "STATUS_COMPLETE_POKE idxField=",
  "STATUS_SLOT0_COMPLETE_POKE",
  "STATUS_COMPLETE_POKE skip",
  "STATUS_COMPLETE_POKE miss",
  "STATUS_COMPLETE_POKE FAIL",
  "AUTO_DETACH_AFTER_LOGIN scheduled",
  "AUTO_DETACH_AFTER_LOGIN done",
  "WRITE260_WATCH armed",
  "WRITE260_MECH_OK",
  "WRITE260_MECH_FAIL",
  "WRITE260 #",
  "WRITE260_TO5_HIT",
  "WRITE260_TO5_MISS",
  "WRITE260 disabled",
  "WRITE260_WATCH_VALIDATED",
  "WRITE260_WATCH_INVALID",
  "PIPE_JOB_BRIDGE=true",
  "PIPE_JOB_BRIDGE_MAM=true",
  "PIPE_WAITER_60=true",
  "PIPE_WAITER_SLOT5_RET_POKE=true",
  "JOB_BRIDGE_ARMED",
  "JOB_BRIDGE_MAM armed",
  "JOB_BRIDGE_MAM skipped",
  "JOB_BRIDGE_WRITE",
  "JOB_BRIDGE_STATUS_CANDIDATE",
  "JOB_BRIDGE_VERDICT",
  "WAITER_60_ARMED",
  "WAITER_60_WRITE",
  "WAITER_60_WRITER",
  "WAITER_60_STORE_SITE",
  "WAITER_60_STORE_HIT",
  "WAITER_60_VERDICT",
  "WAITER_60_HUNT",
  "WAITER_SLOT5_RET_POKE",
  "STATUS_SLOT_POKE",
  "STATUS_COMPLETE_POKE",
  "STATUS_SLOT0_COMPLETE_POKE",
  "LOGIN_STATE_POKE",
  "LOGIN_STATE_SUCC_POKE",
  "LOGIN_COMPLETE_FIND",
  "LOGIN_COMPLETE_STATUS_SCAN",
  "LOGIN_COMPLETE_CHOOSE source=",
  "LOGIN_COMPLETE_CHOOSE skip no-valid",
  "LOGIN_COMPLETE_CALL",
  "LOGIN_COMPLETE_CALL ENTER",
  "LOGIN_COMPLETE_CALL skip vt mismatch",
  "LOGIN_COMPLETE_CALL skip invalid",
  "LOGIN_STATE_SUCC_POKE .*2->5",
  "AUTO_DETACH_AFTER_LOGIN",
  "LOGIN_STATE_CASE enter.*\+0x260=5",
  "LOGIN_STATE_CASE enter.*\+0x260=6",
  "VT20_TRUE",
  "NOT_BUSY2",
  "BUSY_POLL LEAVE JobqHeaderGet ret=0x1",
  "WAITER5_THIS",
  "LOGIN_BUSY_WHY",
  "CNNS_READY_POKE",
  "CNNS_READY_WRITERS",
  "CNNS_VT20 leave.*al=1",
  "OBS_SUCC260",
  "LoginStateLoginComplete.*ENTER",
  "AUTH_LEAN RPC_ENQUEUE #.*cmd=22",
  "cmd=70|REQ logout",
  "LOGIN_STATE Login left BUSY"
)

$counts = @{}
foreach ($countPattern in $countPatterns) {
  $count = (Select-String -LiteralPath $LogPath -Pattern $countPattern).Count
  $counts[$countPattern] = $count
  "{0} = {1}" -f $countPattern, $count
}

Write-Host ""
Write-Host "=== Verdict mode ==="
if (($counts["PIPE_JOB_BRIDGE=true"] -eq 0) -and ($counts["PIPE_ORPHAN_FN_ONLY=true"] -gt 0)) {
  Write-Host "ATTENTION: ce log n'est pas un run JOB_BRIDGE. Il est contamine/axe ORPHAN_FN_ONLY."
  Write-Host "Pour le prochain essai cible, lance: .\tools\run-post-auth-jobbridge-test.ps1"
} elseif ($counts["PIPE_JOB_BRIDGE=true"] -gt 0) {
  Write-Host "OK: ce log est bien un run JOB_BRIDGE."
  if ($counts["JOB_BRIDGE_MAM skipped"] -gt 0 -and $counts["JOB_BRIDGE_MAM armed"] -eq 0) {
    Write-Host "INFO: JOB_BRIDGE etait en poll-only: les snapshots prouvent que les valeurs restent bloquees, mais aucun writer MAM n'etait capture."
  }
} elseif ($counts["PIPE_WAITER_60=true"] -gt 0) {
  Write-Host "OK: ce log est un run WAITER_60."
} elseif ($counts["PIPE_LOGIN_STATE_POKE=true"] -gt 0) {
  Write-Host "OK: ce log est un run LOGIN_STATE_POKE."
} elseif ($counts["PIPE_LOGIN_STATE_SUCC_POKE=true"] -gt 0) {
  Write-Host "OK: ce log est un run LOGIN_STATE_SUCC_POKE."
  if ($counts["PIPE_AUTO_DETACH_AFTER_LOGIN=true"] -gt 0) {
    if ($counts["AUTO_DETACH_AFTER_LOGIN done"] -gt 0) {
      Write-Host "OK: AUTO_DETACH_AFTER_LOGIN s'est execute apres le succes login."
    } elseif ($counts["AUTO_DETACH_AFTER_LOGIN scheduled"] -gt 0) {
      Write-Host "INFO: AUTO_DETACH_AFTER_LOGIN a ete planifie, mais le log ne montre pas le detach final."
    } else {
      Write-Host "ATTENTION: AUTO_DETACH_AFTER_LOGIN etait actif, mais le succes +0x260=6 n'a pas declenche le detach."
    }
  }
} elseif ($counts["PIPE_WAITER_SLOT5_RET_POKE=true"] -gt 0) {
  Write-Host "OK: ce log est un run WAITER_SLOT5_RET_POKE."
} else {
  Write-Host "INFO: ce log n'est ni JOB_BRIDGE ni WAITER_60 ; attention a ne pas l'analyser comme tel."
}

Write-Host ""
Write-Host "=== Dernieres lignes utiles, max $MaxLines ==="

if (Get-Command rg -ErrorAction SilentlyContinue) {
  $matches = @(rg -n $pattern $LogPath)
} else {
  $matches = @(Select-String -LiteralPath $LogPath -Pattern $pattern | ForEach-Object {
    "{0}:{1}" -f $_.LineNumber, $_.Line
  })
}

$matches | Select-Object -Last $MaxLines
