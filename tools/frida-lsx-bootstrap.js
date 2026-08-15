/**
 * LSX_BOOTSTRAP_DISCOVERY — observe how FIFA finds Origin before LSX :3216.
 * Observation only. No memory writes / no Origin online poke / no Login poke.
 *
 * Tags:
 *   LSX_BOOT_CONNECT  LSX_BOOT_PIPE  LSX_BOOT_REG
 *   LSX_BOOT_PROCESS  LSX_BOOT_DLL   LSX_BOOT_WINDOW
 *   LSX_BOOT_SYNC     LSX_BOOT_VERDICT
 */
"use strict";

const MODE = (typeof LSX_BOOT_MODE !== "undefined" ? LSX_BOOT_MODE : "UNKNOWN").toString();
const LOG_PATH =
  typeof LSX_BOOT_LOG !== "undefined" && LSX_BOOT_LOG
    ? LSX_BOOT_LOG.toString()
    : null;

function resolveExport(modName, expName) {
  try {
    const mod = Process.getModuleByName(modName);
    if (mod.findExportByName) return mod.findExportByName(expName);
    if (mod.getExportByName) return mod.getExportByName(expName);
  } catch (_) {}
  try {
    if (Module.getGlobalExportByName) return Module.getGlobalExportByName(expName);
  } catch (_) {}
  try {
    if (typeof Module.findExportByName === "function")
      return Module.findExportByName(modName, expName);
  } catch (_) {}
  return null;
}

const seen = {
  connect: {},
  pipe: {},
  reg: {},
  proc: {},
  dll: {},
  win: {},
  sync: {},
};
let connect3216 = 0;
let originHints = 0;
const firstHits = [];

function now() {
  return Date.now();
}

function emit(tag, msg) {
  const line = "[lsx-boot] ★★★ " + tag + " mode=" + MODE + " " + msg;
  console.log(line);
  if (firstHits.length < 80) firstHits.push(tag + " " + msg);
  if (LOG_PATH) {
    try {
      const f = new File(LOG_PATH, "a");
      f.write(line + "\n");
      f.flush();
      f.close();
    } catch (_) {}
  }
}

function onceKey(bucket, key, maxPerKey) {
  const n = (bucket[key] || 0) + 1;
  bucket[key] = n;
  const cap = maxPerKey || 3;
  return n <= cap;
}

function readUtf16(p, maxChars) {
  if (!p || p.isNull()) return "";
  try {
    return p.readUtf16String(maxChars || 260) || "";
  } catch (_) {
    return "";
  }
}

function readAnsi(p, maxChars) {
  if (!p || p.isNull()) return "";
  try {
    return p.readAnsiString(maxChars || 260) || "";
  } catch (_) {
    return "";
  }
}

function interestingName(s) {
  if (!s) return false;
  // Noise: Frida IPC, PDB/DBG symbol probes (stp-origin_emu.pdb etc.)
  if (/frida-/i.test(s)) return false;
  if (/\.(pdb|dbg)$/i.test(s)) return false;
  return /origin|eadm|ebisu|ea desktop|lsx|\\\\\.\\pipe|origin\.exe|eaCore|OriginSDK|IGO|stp-origin/i.test(
    s,
  );
}

function dumpLoadedModules() {
  const mods = Process.enumerateModules();
  let n = 0;
  for (let i = 0; i < mods.length; i++) {
    const m = mods[i];
    const name = (m.name || "") + " " + (m.path || "");
    if (!/origin|ebisu|eadm|igo|lsx|eaCore|OriginSDK|stp-origin/i.test(name))
      continue;
    n++;
    emit(
      "LSX_BOOT_DLL",
      "api=alreadyLoaded name=" +
        JSON.stringify(m.name) +
        " path=" +
        JSON.stringify(m.path || ""),
    );
  }
  if (n === 0) {
    emit("LSX_BOOT_DLL", "api=alreadyLoaded count=0 (no Origin/Ebisu module yet)");
  }
}

function sockaddrPort(sa) {
  try {
    if (!sa || sa.isNull()) return { ip: "?", port: -1, family: -1 };
    const fam = sa.readU16();
    if (fam === 2) {
      // AF_INET
      const port = ((sa.add(2).readU8() << 8) | sa.add(3).readU8()) >>> 0;
      const a = sa.add(4).readU8();
      const b = sa.add(5).readU8();
      const c = sa.add(6).readU8();
      const d = sa.add(7).readU8();
      return { ip: a + "." + b + "." + c + "." + d, port: port, family: fam };
    }
    if (fam === 23) {
      // AF_INET6 — still log port
      const port = ((sa.add(2).readU8() << 8) | sa.add(3).readU8()) >>> 0;
      return { ip: "ipv6", port: port, family: fam };
    }
    return { ip: "fam" + fam, port: -1, family: fam };
  } catch (_) {
    return { ip: "err", port: -1, family: -1 };
  }
}

function hookConnectLike(modName, exportName) {
  const addr = resolveExport(modName, exportName);
  if (!addr) {
    console.log("[lsx-boot] skip " + exportName + " (not found)");
    return;
  }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      // connect(s, name, namelen) / WSAConnect(s, name, namelen, ...)
      const info = sockaddrPort(args[1]);
      const key = info.ip + ":" + info.port;
      const isLsx = info.port === 3216 || info.port === 3217;
      const isLocal = info.ip === "127.0.0.1" || info.ip === "0.0.0.0";
      if (!isLsx && !(isLocal && info.port > 0 && info.port < 10000)) {
        // still log first few non-local? skip noise
        if (!isLocal) return;
        if (!onceKey(seen.connect, "local:" + key, 2)) return;
      } else {
        if (!onceKey(seen.connect, key, 8)) return;
      }
      if (isLsx) {
        connect3216++;
        originHints++;
      }
      emit(
        "LSX_BOOT_CONNECT",
        "api=" +
          exportName +
          " ip=" +
          info.ip +
          " port=" +
          info.port +
          (isLsx ? " ★LSX_PORT" : ""),
      );
    },
  });
  console.log("[lsx-boot] hooked " + exportName);
}

function hookCreateFile() {
  const names = ["CreateFileW", "CreateFileA"];
  for (let i = 0; i < names.length; i++) {
    const n = names[i];
    const addr = resolveExport("kernel32.dll", n);
    if (!addr) continue;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        const path =
          n === "CreateFileW" ? readUtf16(args[0], 512) : readAnsi(args[0], 512);
        if (!interestingName(path)) return;
        if (!onceKey(seen.pipe, path.toLowerCase(), 5)) return;
        originHints++;
        const isPipe = /\\\\\.\\pipe/i.test(path) || /pipe\\/i.test(path);
        emit(
          isPipe ? "LSX_BOOT_PIPE" : "LSX_BOOT_FILE",
          "api=" + n + " path=" + JSON.stringify(path),
        );
      },
    });
    console.log("[lsx-boot] hooked " + n);
  }
}

function hookRegistry() {
  const apis = [
    ["Advapi32.dll", "RegOpenKeyExW", true],
    ["Advapi32.dll", "RegOpenKeyExA", false],
    ["Advapi32.dll", "RegQueryValueExW", true],
    ["Advapi32.dll", "RegQueryValueExA", false],
    ["Advapi32.dll", "RegGetValueW", true],
    ["Advapi32.dll", "RegGetValueA", false],
  ];
  for (let i = 0; i < apis.length; i++) {
    const dll = apis[i][0];
    const name = apis[i][1];
    const wide = apis[i][2];
    const addr = resolveExport(dll, name);
    if (!addr) continue;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        let label = "";
        // OpenKey: arg1 = subkey; QueryValue: arg1 = value name
        try {
          label = wide ? readUtf16(args[1], 260) : readAnsi(args[1], 260);
        } catch (_) {}
        if (!interestingName(label) && name.indexOf("Open") >= 0) {
          // also try arg2 for some APIs
          try {
            const alt = wide ? readUtf16(args[2], 260) : readAnsi(args[2], 260);
            if (interestingName(alt)) label = alt;
          } catch (_) {}
        }
        if (!interestingName(label)) return;
        if (!onceKey(seen.reg, name + "|" + label.toLowerCase(), 4)) return;
        originHints++;
        emit(
          "LSX_BOOT_REG",
          "api=" + name + " name=" + JSON.stringify(label),
        );
      },
    });
    console.log("[lsx-boot] hooked " + name);
  }
}

function hookProcessDiscovery() {
  const snap = resolveExport("kernel32.dll", "CreateToolhelp32Snapshot");
  if (snap) {
    Interceptor.attach(snap, {
      onEnter: function (args) {
        this.flags = args[0].toInt32();
      },
      onLeave: function (retval) {
        if (!onceKey(seen.proc, "snapshot:" + this.flags, 5)) return;
        emit(
          "LSX_BOOT_PROCESS",
          "api=CreateToolhelp32Snapshot flags=0x" +
            (this.flags >>> 0).toString(16) +
            " ret=" +
            retval,
        );
      },
    });
    console.log("[lsx-boot] hooked CreateToolhelp32Snapshot");
  }

  function hookPe(api) {
    const addr = resolveExport("kernel32.dll", api);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.pe = args[1];
      },
      onLeave: function (retval) {
        if (retval.toInt32() === 0 || !this.pe) return;
        try {
          const name = this.pe.add(0x2c).readUtf16String(260);
          if (!interestingName(name) && !/origin/i.test(name || "")) return;
          if (!onceKey(seen.proc, "pe:" + (name || "").toLowerCase(), 6)) return;
          originHints++;
          emit(
            "LSX_BOOT_PROCESS",
            "api=" + api + " exe=" + JSON.stringify(name),
          );
        } catch (_) {}
      },
    });
    console.log("[lsx-boot] hooked " + api);
  }
  hookPe("Process32FirstW");
  hookPe("Process32NextW");
  hookPe("Process32First");
  hookPe("Process32Next");

  const openProc = resolveExport("kernel32.dll", "OpenProcess");
  if (openProc) {
    Interceptor.attach(openProc, {
      onEnter: function (args) {
        this.pid = args[2].toInt32();
      },
      onLeave: function (retval) {
        if (retval.isNull()) return;
        // resolve name if possible — skip unless we later see Origin; log first few
        if (!onceKey(seen.proc, "open:" + this.pid, 2)) return;
        emit(
          "LSX_BOOT_PROCESS",
          "api=OpenProcess pid=" + this.pid + " handle=" + retval,
        );
      },
    });
    console.log("[lsx-boot] hooked OpenProcess");
  }
}

function hookWindowAndSync() {
  const user32 = "user32.dll";
  const wins = ["FindWindowW", "FindWindowA", "FindWindowExW", "FindWindowExA"];
  for (let i = 0; i < wins.length; i++) {
    const name = wins[i];
    const addr = resolveExport(user32, name);
    if (!addr) continue;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        let a = "";
        let b = "";
        try {
          if (name.indexOf("W") >= 0) {
            a = readUtf16(args[0], 128);
            b = readUtf16(args[1], 128);
          } else {
            a = readAnsi(args[0], 128);
            b = readAnsi(args[1], 128);
          }
        } catch (_) {}
        const combo = (a || "") + "|" + (b || "");
        if (!interestingName(combo) && !interestingName(a) && !interestingName(b))
          return;
        if (!onceKey(seen.win, name + combo.toLowerCase(), 4)) return;
        originHints++;
        emit(
          "LSX_BOOT_WINDOW",
          "api=" +
            name +
            " class=" +
            JSON.stringify(a) +
            " title=" +
            JSON.stringify(b),
        );
      },
    });
    console.log("[lsx-boot] hooked " + name);
  }

  // [dll, api, wide, nameArgIndex]
  const syncApis = [
    ["kernel32.dll", "CreateMutexW", true, 2],
    ["kernel32.dll", "CreateMutexA", false, 2],
    ["kernel32.dll", "OpenMutexW", true, 2],
    ["kernel32.dll", "OpenMutexA", false, 2],
    ["kernel32.dll", "CreateEventW", true, 3],
    ["kernel32.dll", "CreateEventA", false, 3],
    ["kernel32.dll", "OpenEventW", true, 2],
    ["kernel32.dll", "OpenEventA", false, 2],
  ];
  for (let i = 0; i < syncApis.length; i++) {
    const dll = syncApis[i][0];
    const name = syncApis[i][1];
    const wide = syncApis[i][2];
    const nameIdx = syncApis[i][3];
    const addr = resolveExport(dll, name);
    if (!addr) continue;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        let nm = "";
        try {
          nm = wide
            ? readUtf16(args[nameIdx], 260)
            : readAnsi(args[nameIdx], 260);
        } catch (_) {}
        if (!interestingName(nm)) return;
        if (!onceKey(seen.sync, name + "|" + nm.toLowerCase(), 4)) return;
        originHints++;
        emit(
          "LSX_BOOT_SYNC",
          "api=" + name + " name=" + JSON.stringify(nm),
        );
      },
    });
    console.log("[lsx-boot] hooked " + name);
  }
}

function hookLoadLibrary() {
  const apis = [
    ["kernel32.dll", "LoadLibraryW", true],
    ["kernel32.dll", "LoadLibraryA", false],
    ["kernel32.dll", "LoadLibraryExW", true],
    ["kernel32.dll", "LoadLibraryExA", false],
  ];
  for (let i = 0; i < apis.length; i++) {
    const dll = apis[i][0];
    const name = apis[i][1];
    const wide = apis[i][2];
    const addr = resolveExport(dll, name);
    if (!addr) continue;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        const path = wide ? readUtf16(args[0], 512) : readAnsi(args[0], 512);
        if (!interestingName(path)) return;
        if (!onceKey(seen.dll, path.toLowerCase(), 5)) return;
        originHints++;
        emit(
          "LSX_BOOT_DLL",
          "api=" + name + " path=" + JSON.stringify(path),
        );
      },
    });
    console.log("[lsx-boot] hooked " + name);
  }
}

function armVerdictTimer() {
  setTimeout(function () {
    const verdict =
      connect3216 > 0
        ? "REACHED_LSX_CONNECT"
        : originHints > 0
          ? "ORIGIN_HINTS_NO_LSX_CONNECT"
          : "NO_ORIGIN_BOOTSTRAP_SEEN";
    emit(
      "LSX_BOOT_VERDICT",
      "verdict=" +
        verdict +
        " connect3216=" +
        connect3216 +
        " originHints=" +
        originHints +
        " first=[" +
        firstHits.slice(0, 12).join(" || ") +
        "]",
    );
  }, 90000);
}

console.log(
  "[lsx-boot] LSX_BOOTSTRAP_DISCOVERY armed mode=" +
    MODE +
    " (no pokes). Launch/enter UT; wait ~90s for VERDICT.",
);
emit("LSX_BOOT_START", "pid=" + Process.id);
dumpLoadedModules();

hookConnectLike("ws2_32.dll", "connect");
hookConnectLike("ws2_32.dll", "WSAConnect");
hookCreateFile();
hookRegistry();
hookProcessDiscovery();
hookWindowAndSync();
hookLoadLibrary();
armVerdictTimer();
