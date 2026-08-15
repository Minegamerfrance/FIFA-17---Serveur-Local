/**
 * Watch FIFA17 TCP connections (simple, reliable).
 * Usage: npx tsx tools/watch-fifa-net.ts
 */
import { execSync } from "node:child_process";

function ps(command: string): string {
  try {
    return execSync(
      `powershell -NoProfile -ExecutionPolicy Bypass -Command "${command.replace(/"/g, '\\"')}"`,
      { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], windowsHide: true },
    );
  } catch {
    return "";
  }
}

console.log("Watch FIFA17 — garde le jeu ouvert sur l'erreur UT. Ctrl+C pour stop.\n");

let last = "";
setInterval(() => {
  // tasklist is more reliable than nested CIM in some environments
  const task = execSync("tasklist /FI \"IMAGENAME eq FIFA17.exe\" /FO CSV /NH", {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    windowsHide: true,
  }).trim();

  if (!task || task.toLowerCase().includes("no tasks") || task.toLowerCase().includes("aucune")) {
    // also try lowercase / other
    const any = ps(
      "Get-Process | Where-Object { $_.ProcessName -match 'fifa|stp-fifa|stp-selector' } | Select-Object Id,ProcessName,MainWindowTitle | Format-Table -AutoSize | Out-String",
    ).trim();
    const msg = any
      ? `[other]\n${any}`
      : "[waiting] FIFA17.exe introuvable. Dans le Gestionnaire des taches, verifie le nom exact du process.";
    if (msg !== last) {
      console.log(msg);
      last = msg;
    }
    return;
  }

  // CSV: "FIFA17.exe","952","Console","1","1,234 K"
  const m = task.match(/"FIFA17\.exe","(\d+)"/i);
  const pid = m?.[1];
  if (!pid) {
    console.log("parse fail:", task);
    return;
  }

  const conns = ps(
    `Get-NetTCPConnection -OwningProcess ${pid} -ErrorAction SilentlyContinue | Select-Object State,LocalPort,RemoteAddress,RemotePort | Sort-Object RemoteAddress,RemotePort | Format-Table -AutoSize | Out-String -Width 200`,
  ).trim();

  const msg = `FOUND FIFA17.exe pid=${pid}\n${conns || "(aucune connexion TCP)"}`;
  if (msg !== last) {
    console.log(`\n=== ${new Date().toLocaleTimeString()} ===`);
    console.log(msg);
    last = msg;
  }
}, 1500);
