/**
 * STP_ORIGIN_OBS — observation-only reverse of stp-origin_emu.dll
 *
 * Tags:
 *   STP_LOAD  STP_EXPORT_CALL  STP_CONNECT_4216
 *   STP_SEND  STP_RECV  STP_PIPE  STP_CALLBACK
 *   STP_ONLINE_RESULT  STP_LOGIN_RESULT  STP_VERDICT
 *   STP_BIND  STP_IMPORT  STP_GETPROC
 */
"use strict";

const MODE = (typeof STP_OBS_MODE !== "undefined" ? STP_OBS_MODE : "OBS").toString();
const DLL_NAME = "stp-origin_emu.dll";

let dllMod = null; // { name, base, size, path }
const socks4216 = {}; // fd -> true
let connect4216 = 0;
let sendN = 0;
let recvN = 0;
let exportCalls = 0;
let loadSeen = 0;
const firstHits = [];
const hookedExports = {};

function resolveExport(modName, expName) {
  try {
    const mod = Process.getModuleByName(modName);
    if (mod.findExportByName) return mod.findExportByName(expName);
    if (mod.getExportByName) return mod.getExportByName(expName);
  } catch (e) {}
  try {
    if (Module.getGlobalExportByName) return Module.getGlobalExportByName(expName);
  } catch (e) {}
  return null;
}

function emit(tag, msg) {
  const line = "[stp] ★★★ " + tag + " mode=" + MODE + " " + msg;
  console.log(line);
  if (firstHits.length < 100) firstHits.push(tag + " " + msg);
}

function hexPreview(ptr, n) {
  try {
    if (!ptr || ptr.isNull()) return "";
    const m = Math.min(n || 64, 128);
    const buf = ptr.readByteArray(m);
    if (!buf) return "";
    const u8 = new Uint8Array(buf);
    const parts = [];
    let ascii = "";
    for (let i = 0; i < u8.length; i++) {
      parts.push(("0" + u8[i].toString(16)).slice(-2));
      const c = u8[i];
      ascii += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : ".";
    }
    return "hex=" + parts.join("") + " ascii=" + JSON.stringify(ascii);
  } catch (e) {
    return "hex=(err)";
  }
}

function readUtf16(p, maxChars) {
  if (!p || p.isNull()) return "";
  try {
    return p.readUtf16String(maxChars || 260) || "";
  } catch (e) {
    return "";
  }
}

function readAnsi(p, maxChars) {
  if (!p || p.isNull()) return "";
  try {
    return p.readAnsiString(maxChars || 260) || "";
  } catch (e) {
    return "";
  }
}

function inDll(addr) {
  if (!dllMod || !addr) return false;
  try {
    const a = ptr(addr);
    const base = dllMod.base;
    const end = base.add(dllMod.size);
    return a.compare(base) >= 0 && a.compare(end) < 0;
  } catch (e) {
    return false;
  }
}

function callerInDll() {
  try {
    const bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
    for (let i = 0; i < Math.min(bt.length, 8); i++) {
      if (inDll(bt[i])) return bt[i];
    }
    // FALLBACK: return address often in lr/rip stack — use first bt
  } catch (e) {}
  return null;
}

function sockaddrInfo(sa) {
  try {
    if (!sa || sa.isNull()) return { ip: "?", port: -1 };
    const fam = sa.readU16();
    if (fam === 2) {
      const port = ((sa.add(2).readU8() << 8) | sa.add(3).readU8()) >>> 0;
      const a = sa.add(4).readU8();
      const b = sa.add(5).readU8();
      const c = sa.add(6).readU8();
      const d = sa.add(7).readU8();
      return { ip: a + "." + b + "." + c + "." + d, port: port, family: fam };
    }
    return { ip: "fam" + fam, port: -1, family: fam };
  } catch (e) {
    return { ip: "err", port: -1 };
  }
}

function refreshDllModule() {
  const mods = Process.enumerateModules();
  for (let i = 0; i < mods.length; i++) {
    const m = mods[i];
    if ((m.name || "").toLowerCase() === DLL_NAME.toLowerCase()) {
      dllMod = { name: m.name, base: m.base, size: m.size, path: m.path || "" };
      return dllMod;
    }
  }
  return null;
}

function listExports() {
  if (!dllMod) return [];
  try {
    const m = Process.getModuleByName(DLL_NAME);
    if (m.enumerateExports) return m.enumerateExports();
  } catch (e) {}
  try {
    return Module.enumerateExports(DLL_NAME);
  } catch (e) {}
  return [];
}

function listImports() {
  if (!dllMod) return [];
  try {
    const m = Process.getModuleByName(DLL_NAME);
    if (m.enumerateImports) return m.enumerateImports();
  } catch (e) {}
  try {
    return Module.enumerateImports(DLL_NAME);
  } catch (e) {}
  return [];
}

function hookOneExport(exp) {
  const key = exp.name || exp.address.toString();
  if (hookedExports[key]) return;
  if (!exp.address) return;
  hookedExports[key] = true;
  try {
    Interceptor.attach(exp.address, {
      onEnter: function (args) {
        exportCalls++;
        this._exp = exp.name || "?";
        this._a0 = args[0];
        this._a1 = args[1];
        this._a2 = args[2];
        this._a3 = args[3];
        emit(
          "STP_EXPORT_CALL",
          "ENTER name=" +
            this._exp +
            " addr=" +
            exp.address +
            " a0=" +
            args[0] +
            " a1=" +
            args[1] +
            " a2=" +
            args[2] +
            " a3=" +
            args[3],
        );
      },
      onLeave: function (retval) {
        emit(
          "STP_EXPORT_CALL",
          "LEAVE name=" +
            this._exp +
            " ret=" +
            retval +
            " ret32=0x" +
            (retval.toInt32() >>> 0).toString(16),
        );
        // If DllInit returns a pointer, treat as possible vtable/callback table
        try {
          if (this._exp === "DllInit" && !retval.isNull()) {
            emit(
              "STP_CALLBACK",
              "DllInit.retPtr=" +
                retval +
                " peek=" +
                hexPreview(retval, 32),
            );
            // try read first few qwords as possible fn ptrs in dll
            for (let i = 0; i < 8; i++) {
              const q = retval.add(i * 8).readPointer();
              if (inDll(q)) {
                emit(
                  "STP_CALLBACK",
                  "DllInit.table[" + i + "]=" + q + " (in-dll)",
                );
                hookCodePtr(q, "DllInit.table" + i);
              }
            }
          }
        } catch (e) {}
      },
    });
    console.log("[stp] hooked export " + (exp.name || exp.address));
  } catch (e) {
    console.log("[stp] fail hook export " + key + " " + e);
  }
}

function hookCodePtr(addr, label) {
  const key = "code:" + addr;
  if (hookedExports[key]) return;
  hookedExports[key] = true;
  try {
    Interceptor.attach(addr, {
      onEnter: function (args) {
        emit(
          "STP_CALLBACK",
          "ENTER label=" +
            label +
            " addr=" +
            addr +
            " a0=" +
            args[0] +
            " a1=" +
            args[1] +
            " a2=" +
            args[2],
        );
      },
      onLeave: function (retval) {
        emit(
          "STP_CALLBACK",
          "LEAVE label=" + label + " ret=" + retval,
        );
      },
    });
  } catch (e) {}
}

function onDllReady(reason) {
  if (!refreshDllModule()) return;
  loadSeen++;
  const exps = listExports();
  const imps = listImports();
  const expNames = [];
  for (let i = 0; i < exps.length; i++) {
    expNames.push((exps[i].type || "?") + ":" + (exps[i].name || exps[i].address));
  }
  emit(
    "STP_LOAD",
    "reason=" +
      reason +
      " base=" +
      dllMod.base +
      " size=0x" +
      dllMod.size.toString(16) +
      " path=" +
      JSON.stringify(dllMod.path) +
      " exports=" +
      expNames.join(",") +
      " nExp=" +
      exps.length +
      " nImp=" +
      imps.length,
  );

  // interesting imports
  for (let i = 0; i < imps.length; i++) {
    const im = imps[i];
    const n = (im.name || "") + "";
    if (/connect|send|recv|WSA|CreateFile|Reg|socket|bind|listen|accept|GetProc/i.test(n)) {
      emit(
        "STP_IMPORT",
        "mod=" +
          (im.module || "?") +
          " name=" +
          n +
          " addr=" +
          (im.address || "0"),
      );
    }
  }

  for (let i = 0; i < exps.length; i++) {
    if (exps[i].type === "function" || !exps[i].type) hookOneExport(exps[i]);
  }

  // Always try DllInit by name
  try {
    const m = Process.getModuleByName(DLL_NAME);
    const di = m.findExportByName
      ? m.findExportByName("DllInit")
      : m.getExportByName
        ? m.getExportByName("DllInit")
        : null;
    if (di) hookOneExport({ name: "DllInit", address: di, type: "function" });
  } catch (e) {}
}

function hookLoadLibrary() {
  const apis = [
    ["LoadLibraryW", true],
    ["LoadLibraryA", false],
    ["LoadLibraryExW", true],
    ["LoadLibraryExA", false],
  ];
  for (let i = 0; i < apis.length; i++) {
    const name = apis[i][0];
    const wide = apis[i][1];
    const addr = resolveExport("kernel32.dll", name);
    if (!addr) continue;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.path = wide ? readUtf16(args[0], 512) : readAnsi(args[0], 512);
        this.hit = /stp-origin_emu/i.test(this.path || "");
      },
      onLeave: function (retval) {
        if (!this.hit) return;
        emit(
          "STP_LOAD",
          "api=" + name + " path=" + JSON.stringify(this.path) + " hmod=" + retval,
        );
        // UPX unpacks on first call — poll shortly
        const delays = [0, 50, 200, 500, 1500, 3000];
        for (let d = 0; d < delays.length; d++) {
          const ms = delays[d];
          setTimeout(function () {
            onDllReady("post-load+" + ms + "ms");
          }, ms);
        }
      },
    });
    console.log("[stp] hooked " + name);
  }
}

function hookVirtualProtectUnpack() {
  const addr = resolveExport("kernel32.dll", "VirtualProtect");
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.addr = args[0];
      this.size = args[1].toInt32();
    },
    onLeave: function (retval) {
      if (!dllMod) refreshDllModule();
      if (!dllMod) return;
      if (!inDll(this.addr) && !(dllMod && this.addr.equals && false)) {
        // also if protect targets inside dll
        if (!inDll(this.addr)) return;
      }
      if (!inDll(this.addr)) return;
      emit(
        "STP_LOAD",
        "VirtualProtect unpack-ish addr=" +
          this.addr +
          " size=0x" +
          (this.size >>> 0).toString(16) +
          " ret=" +
          retval,
      );
      setTimeout(function () {
        onDllReady("after-VirtualProtect");
      }, 20);
    },
  });
  console.log("[stp] hooked VirtualProtect");
}

function hookGetProcAddress() {
  const addr = resolveExport("kernel32.dll", "GetProcAddress");
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.mod = args[0];
      this.name = readAnsi(args[1], 256);
      this.fromDll = false;
      try {
        const ret = this.returnAddress;
        this.fromDll = inDll(ret);
      } catch (e) {}
    },
    onLeave: function (retval) {
      if (!this.fromDll && !/origin|ebisu|igo|lsx|DllInit/i.test(this.name || ""))
        return;
      if (!this.fromDll && !dllMod) return;
      // log if caller in dll OR resolving interesting name while dll loaded
      let from = false;
      try {
        from = inDll(this.context.returnAddress || ptr(0));
      } catch (e) {}
      // Frida: use backtrace
      const c = callerInDll.call(this);
      if (!c && !/origin|ebisu|DllInit|GetAuth|Online|Login|Persona/i.test(this.name || ""))
        return;
      emit(
        "STP_GETPROC",
        "name=" +
          JSON.stringify(this.name) +
          " ret=" +
          retval +
          (c ? " callerInDll=" + c : ""),
      );
    },
  });
  console.log("[stp] hooked GetProcAddress");
}

function hookNet() {
  function attachConnect(api) {
    const addr = resolveExport("ws2_32.dll", api);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.info = sockaddrInfo(args[1]);
        this.from = callerInDll.call(this);
      },
      onLeave: function (retval) {
        const info = this.info;
        const is4216 = info.port === 4216;
        const fromDll = !!this.from || (dllMod && is4216);
        if (!is4216 && !this.from) {
          // still log connect from dll to any port
          if (!this.from) return;
        }
        if (is4216) {
          connect4216++;
          socks4216[this.fd] = true;
        }
        const tag = is4216 ? "STP_CONNECT_4216" : "STP_CONNECT_DLL";
        emit(
          tag,
          "api=" +
            api +
            " fd=" +
            this.fd +
            " ip=" +
            info.ip +
            " port=" +
            info.port +
            " ret=" +
            retval.toInt32() +
            (this.from ? " callerDll=" + this.from : "") +
            (is4216 ? " ★4216" : " (dll-caller)"),
        );
      },
    });
    console.log("[stp] hooked " + api);
  }
  attachConnect("connect");
  attachConnect("WSAConnect");

  function attachBindListen(api) {
    const addr = resolveExport("ws2_32.dll", api);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.from = callerInDll.call(this);
        if (api === "bind") this.info = sockaddrInfo(args[1]);
        else this.info = { ip: "?", port: -1 };
        this.fd = args[0].toInt32();
      },
      onLeave: function (retval) {
        if (!this.from && !(this.info && this.info.port === 4216)) return;
        emit(
          "STP_BIND",
          "api=" +
            api +
            " fd=" +
            this.fd +
            " ip=" +
            this.info.ip +
            " port=" +
            this.info.port +
            " ret=" +
            retval.toInt32() +
            (this.from ? " callerDll=" + this.from : ""),
        );
      },
    });
    console.log("[stp] hooked " + api);
  }
  attachBindListen("bind");
  attachBindListen("listen");
  attachBindListen("accept");

  function attachXfer(api, isSend) {
    const addr = resolveExport("ws2_32.dll", api);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
        this.from = callerInDll.call(this);
        this.track = !!socks4216[this.fd] || !!this.from;
      },
      onLeave: function (retval) {
        if (!this.track) return;
        const n = retval.toInt32();
        if (isSend) sendN++;
        else recvN++;
        emit(
          isSend ? "STP_SEND" : "STP_RECV",
          "api=" +
            api +
            " fd=" +
            this.fd +
            " lenArg=" +
            this.len +
            " ret=" +
            n +
            " " +
            hexPreview(this.buf, Math.min(this.len > 0 ? this.len : 64, 96)) +
            (socks4216[this.fd] ? " sock4216=1" : "") +
            (this.from ? " callerDll=" + this.from : ""),
        );
      },
    });
    console.log("[stp] hooked " + api);
  }
  attachXfer("send", true);
  attachXfer("recv", false);
  // WSASend/WSARecv — best-effort first buffer
  const wsaSend = resolveExport("ws2_32.dll", "WSASend");
  if (wsaSend) {
    Interceptor.attach(wsaSend, {
      onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.from = callerInDll.call(this);
        this.track = !!socks4216[this.fd] || !!this.from;
        this.buf = ptr(0);
        this.len = 0;
        try {
          const lpBuffers = args[1];
          this.len = lpBuffers.readU32();
          this.buf = lpBuffers.add(Process.pointerSize === 8 ? 8 : 4).readPointer();
        } catch (e) {}
      },
      onLeave: function (retval) {
        if (!this.track) return;
        sendN++;
        emit(
          "STP_SEND",
          "api=WSASend fd=" +
            this.fd +
            " ret=" +
            retval.toInt32() +
            " " +
            hexPreview(this.buf, Math.min(this.len || 64, 96)) +
            (socks4216[this.fd] ? " sock4216=1" : ""),
        );
      },
    });
    console.log("[stp] hooked WSASend");
  }
  const wsaRecv = resolveExport("ws2_32.dll", "WSARecv");
  if (wsaRecv) {
    Interceptor.attach(wsaRecv, {
      onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.from = callerInDll.call(this);
        this.track = !!socks4216[this.fd] || !!this.from;
        this.lpBuffers = args[1];
      },
      onLeave: function (retval) {
        if (!this.track) return;
        recvN++;
        let buf = ptr(0);
        let len = 0;
        try {
          len = this.lpBuffers.readU32();
          buf = this.lpBuffers.add(Process.pointerSize === 8 ? 8 : 4).readPointer();
        } catch (e) {}
        emit(
          "STP_RECV",
          "api=WSARecv fd=" +
            this.fd +
            " ret=" +
            retval.toInt32() +
            " " +
            hexPreview(buf, Math.min(len || 64, 96)) +
            (socks4216[this.fd] ? " sock4216=1" : ""),
        );
      },
    });
    console.log("[stp] hooked WSARecv");
  }
}

function hookCreateFile() {
  const names = [
    ["CreateFileW", true],
    ["CreateFileA", false],
  ];
  for (let i = 0; i < names.length; i++) {
    const name = names[i][0];
    const wide = names[i][1];
    const addr = resolveExport("kernel32.dll", name);
    if (!addr) continue;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.path = wide ? readUtf16(args[0], 512) : readAnsi(args[0], 512);
        this.from = callerInDll.call(this);
      },
      onLeave: function (retval) {
        if (!this.from) return;
        emit(
          "STP_PIPE",
          "api=" +
            name +
            " path=" +
            JSON.stringify(this.path) +
            " ret=" +
            retval +
            " callerDll=" +
            this.from,
        );
      },
    });
    console.log("[stp] hooked " + name);
  }
}

function hookOriginCheckOnlineObs() {
  // Best-effort: known FIFA wrapper RVA from prior work (base+0x70da3b0 on older ASLR)
  // Prefer symbol scan for "OriginCheckOnline" if module FIFA17
  try {
    const fifa = Process.getModuleByName("FIFA17.exe");
    // pattern not reliable — hook by absolute from previous sessions only if matches size
    // Skip hardcoding ASLR. Instead scan exports — none.
    // Soft: intercept when online string appears via send ascii
  } catch (e) {}
}

function armVerdict() {
  setTimeout(function () {
    const verdict =
      connect4216 > 0 && (sendN > 0 || recvN > 0)
        ? "STP_TALKS_4216"
        : connect4216 > 0
          ? "STP_CONNECT_4216_NO_XFER"
          : loadSeen > 0
            ? "STP_LOADED_NO_4216"
            : "STP_NOT_LOADED";
    emit(
      "STP_VERDICT",
      "verdict=" +
        verdict +
        " loadSeen=" +
        loadSeen +
        " connect4216=" +
        connect4216 +
        " send=" +
        sendN +
        " recv=" +
        recvN +
        " exportCalls=" +
        exportCalls +
        " dllBase=" +
        (dllMod ? dllMod.base : "0") +
        " first=[" +
        firstHits.slice(0, 15).join(" || ") +
        "]",
    );
  }, 90000);
}

console.log(
  "[stp] STP_ORIGIN_OBS armed mode=" + MODE + " — spawn/attach FIFA, wait ~90s",
);
emit("STP_LOAD", "script-start pid=" + Process.id);

// If already loaded (late attach)
if (refreshDllModule()) onDllReady("already-present");

hookLoadLibrary();
hookVirtualProtectUnpack();
hookGetProcAddress();
hookNet();
hookCreateFile();
hookOriginCheckOnlineObs();
armVerdict();
