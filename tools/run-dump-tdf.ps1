# Dump live TDF type member tables from FIFA17.exe
$ErrorActionPreference = "Stop"
$here = Split-Path $PSScriptRoot -Parent
Set-Location $here

$py = "C:\Users\Mineg\AppData\Local\Programs\Python\Python312\python.exe"
if (-not (Test-Path $py)) { $py = "python" }

$proc = Get-Process -Name "FIFA17" -ErrorAction SilentlyContinue
if (-not $proc) {
  Write-Host "Ouvre FIFA 17 d'abord."
  exit 1
}

Write-Host "Dump TDF types (ServerInstanceRequest/Info)…"
Write-Host "Laisse tourner pendant UT si tu veux les ★ UNKNOWN MEMBER."
& $py -c @"
import frida, sys, time
from pathlib import Path
code = Path(r'tools/frida-dump-tdf.js').read_text(encoding='utf-8')
d = frida.get_local_device()
procs = [p for p in d.enumerate_processes() if p.name.lower()=='fifa17.exe']
if not procs:
    print('FIFA17.exe not running')
    sys.exit(1)
pid = procs[0].pid
print('attach', pid)
s = d.attach(pid)
def on_msg(m, _data):
    t = m.get('type')
    if t == 'send':
        print(m['payload'], flush=True)
    elif t == 'log':
        print(m.get('payload', m), flush=True)
    elif t == 'error':
        print(m.get('stack') or m, flush=True)
    else:
        print(m, flush=True)
sc = s.create_script(code)
sc.on('message', on_msg)
sc.load()
# Stay alive briefly for static dump only (do NOT run together with ssl-bypass)
print('=== dump finished ===', flush=True)
time.sleep(1)
"@
