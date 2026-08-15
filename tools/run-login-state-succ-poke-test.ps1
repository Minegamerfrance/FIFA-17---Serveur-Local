$ErrorActionPreference = "Stop"

$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location $projectRoot
& (Join-Path $PSScriptRoot "reset-pipeline-env.ps1")

# Test cible apres le run WAITER_SLOT5_RET_POKE:
# - Auth/10 est consomme.
# - JobqHeaderGet retourne READY.
# - WaiterBusySlot5 peut etre force a 0, mais LoginState reste +0x260=2.
# Le switch dump prouve: case 5 -> chemin succes natif, qui ecrit ensuite
# +0x260=6 et +0x264=5. On force donc uniquement 2 -> 5, une seule fois,
# quand Auth/10 est actif et JobqHeaderGet est READY.
#
# Variante SDB_AUTH_FLAGS:
# - garder le deblocage minimal du login;
# - ne plus forcer slot0;
# - ne plus forcer ret=6 -> DONE=3: ce poke est prouve inutile sur l'ecran SDB.
# - tester uniquement les flags Auth cote serveur (AGUP=0 / SPAM=1).
$env:PIPE_FORCE_ADDR = "1"
$env:PIPE_FIX_TIMER = "1"
$env:PIPE_PING_OBS = "0"
$env:PIPE_CRASH_OBS = "1"
$env:PIPE_CRASH_FIX = "1"
$env:PIPE_RESOLVER_CLEAN_FIX = "1"
$env:PIPE_ORIGIN_ONLINE_FIX = "1"
$env:PIPE_ORIGIN_AUTHCODE_FIX = "1"
$env:PIPE_ORIGIN_VERSION_FIX = "1"
$env:PIPE_EBISU_FIX = "1"
$env:PIPE_STATUS_SLOT_POKE = "1"
$env:PIPE_STATUS_COMPLETE_POKE = "1"
$env:PIPE_STATUS_COMPLETE_IDX = "2"
$env:PIPE_STATUS_SLOT0_COMPLETE_POKE = "0"
$env:PIPE_CNNS_READY_POKE = "1"
$env:PIPE_LOGIN_STATE_POKE = "0"
$env:PIPE_LOGIN_STATE_SUCC_POKE = "1"
$env:PIPE_LOGIN_COMPLETE_CALL = "1"
$env:PIPE_LOGIN_RET_DONE_POKE = "1"
$env:PIPE_LOGIN_RET_DONE_VALUE = "3"
$env:PIPE_AUTO_DETACH_AFTER_LOGIN = "0"
$env:PIPE_AUTH_WAITER_DONE_POKE = "1"
$env:PIPE_AUTH_JOBQ_DONE_POKE = "1"
$env:PIPE_LOGIN_260_MAM = "0"
$env:PIPE_EXT_DISPATCH = "0"
$env:PIPE_ORPHAN_LISTENER = "0"
$env:PIPE_ORPHAN_STATIC_ONLY = "0"
$env:PIPE_ORPHAN_FN_ONLY = "0"
$env:PIPE_FAIL16 = "0"
$env:PIPE_AUTH10_COMPLETE = "1"
$env:PIPE_JOB_BRIDGE = "0"
$env:PIPE_JOB_BRIDGE_MAM = "0"
$env:PIPE_WAITER_60 = "0"
$env:PIPE_WAITER_SLOT5_RET_POKE = "1"
$env:PIPE_SDB_UI = "1"

Write-Host "Test courant: FAIL13-recover + CONN_GATE neutralize + SUCC/COMPLETE/RET_DONE/SLOT5 + SDB_UI."
Write-Host "Chercher: FAIL_13 recovered, CONN_GATE neutralize, ClientKeyExchange / BLAZE_CKE."
Write-Host "IMPORTANT: restart FIFA frais AVANT ce probe."
Write-Host "Puis: WAITER_SLOT5_RET_POKE succ6-ret, fin spam Login."
Write-Host "On Partage: press OK / toggle Origin. Watch: SDB_UI_HIT PARTAGE_OK."
Write-Host "If FAIL_13 again or spam Login after ~40s, Ctrl+C."
& (Join-Path $PSScriptRoot "run-pipeline-probe.ps1")
