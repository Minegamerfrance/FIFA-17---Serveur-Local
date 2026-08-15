# OBSERVE Redirector — dump what FIFA asks/sees (no format guessing)
$ErrorActionPreference = "Stop"
$here = Split-Path $PSScriptRoot -Parent
Set-Location $here

$py = "C:\Users\Mineg\AppData\Local\Programs\Python\Python312\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

$proc = Get-Process -Name "FIFA17" -ErrorAction SilentlyContinue
if (-not $proc) {
  Write-Host "Ouvre FIFA 17 d'abord, puis relance ce script."
  exit 1
}

$logDir = Join-Path $here "tools\versions\observe"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$log = Join-Path $logDir ("frida-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".log")
Write-Host "Observe log → $log"
Write-Host "Va dans Ultimate Team, attends le redirector, puis reviens."

& $py -c @"
import frida, sys, time
from pathlib import Path
code = Path(r'tools/frida-observe-redirector.js').read_text(encoding='utf-8')
log = Path(r'$($log.Replace('\','\\'))')
d = frida.get_local_device()
procs = [p for p in d.enumerate_processes() if p.name.lower()=='fifa17.exe']
pid = procs[0].pid
print('attach', pid)
s = d.attach(pid)
def on_msg(m, _data):
    line = ''
    t = m.get('type')
    if t == 'send':
        line = str(m['payload'])
    elif t == 'log':
        line = str(m.get('payload', m))
    elif t == 'error':
        line = str(m.get('stack') or m)
    else:
        line = str(m)
    print(line, flush=True)
    with log.open('a', encoding='utf-8') as f:
        f.write(line + '\n')
sc = s.create_script(code)
sc.on('message', on_msg)
sc.load()
print('=== observe running — Ctrl+C after UT redirector attempt ===', flush=True)
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print('=== observe stopped ===', flush=True)
"@
