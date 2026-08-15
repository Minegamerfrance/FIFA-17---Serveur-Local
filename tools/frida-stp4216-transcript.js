/**
 * STP4216_PLAINTEXT_TRANSCRIPT
 * Reassemble TCP frames on :4216 split by 0x00 terminator.
 * Offline AES decrypt happens in Python (lsx_crypto).
 * Observation only — no FIFA memory pokes, no STP reply injection.
 */
"use strict";

const MODE = (typeof STP_OBS_MODE !== "undefined" ? STP_OBS_MODE : "TRANSCRIPT").toString();
const DLL_NAME = "stp-origin_emu.dll";
const LSX_PORT = 4216;

let dllMod = null;
let listenFd = -1;
const socks = {}; // fd -> meta
const rxBuf = {}; // fd -> Array of bytes pending
const txBuf = {}; // fd -> Array of bytes pending
let frameSeq = 0;
let onlineSeen = null;
const firstHits = [];

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
  const line = "[stp4216] ★★★ " + tag + " mode=" + MODE + " " + msg;
  console.log(line);
  if (firstHits.length < 100) firstHits.push(tag);
}

function ts() {
  return Date.now();
}

function inDll(addr) {
  if (!dllMod || !addr) return false;
  try {
    const a = ptr(addr);
    return a.compare(dllMod.base) >= 0 && a.compare(dllMod.base.add(dllMod.size)) < 0;
  } catch (e) {
    return false;
  }
}

function callerInDll(ctx) {
  try {
    const bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
    for (let i = 0; i < Math.min(bt.length, 8); i++) {
      if (inDll(bt[i])) return bt[i].toString();
    }
  } catch (e) {}
  return null;
}

function sockaddrInfo(sa) {
  try {
    if (!sa || sa.isNull() || sa.readU16() !== 2) return { ip: "?", port: -1 };
    const port = ((sa.add(2).readU8() << 8) | sa.add(3).readU8()) >>> 0;
    return {
      ip:
        sa.add(4).readU8() +
        "." +
        sa.add(5).readU8() +
        "." +
        sa.add(6).readU8() +
        "." +
        sa.add(7).readU8(),
      port: port,
    };
  } catch (e) {
    return { ip: "err", port: -1 };
  }
}

function querySock(fd, peer) {
  const api = peer ? "getpeername" : "getsockname";
  const fn = resolveExport("ws2_32.dll", api);
  if (!fn) return { ip: "?", port: -1 };
  const getname = new NativeFunction(fn, "int", ["int", "pointer", "pointer"]);
  const sa = Memory.alloc(28);
  const len = Memory.alloc(4);
  len.writeU32(28);
  if (getname(fd, sa, len) !== 0) return { ip: "?", port: -1 };
  return sockaddrInfo(sa);
}

function bytesToHex(u8) {
  const parts = [];
  for (let i = 0; i < u8.length; i++) {
    parts.push(("0" + u8[i].toString(16)).slice(-2));
  }
  return parts.join("");
}

function readBytes(p, n) {
  try {
    return new Uint8Array(p.readByteArray(n));
  } catch (e) {
    return new Uint8Array(0);
  }
}

function isTrackedFd(fd) {
  const s = socks[fd];
  if (!s) return false;
  if (s.port === LSX_PORT) return true;
  if (s.role && String(s.role).indexOf("4216") >= 0) return true;
  if (s.role && String(s.role).indexOf("Fifa") >= 0) return true;
  if (s.role && String(s.role).indexOf("lsx") >= 0) return true;
  if (s.parentListen === listenFd) return true;
  return false;
}

function ensureBuf(map, fd) {
  if (!map[fd]) map[fd] = [];
  return map[fd];
}

function appendAndSplit(map, fd, chunk, direction) {
  const buf = ensureBuf(map, fd);
  for (let i = 0; i < chunk.length; i++) buf.push(chunk[i]);
  // split on 0x00
  while (true) {
    let idx = -1;
    for (let i = 0; i < buf.length; i++) {
      if (buf[i] === 0) {
        idx = i;
        break;
      }
    }
    if (idx < 0) break;
    const frame = buf.splice(0, idx + 1); // include NUL
    emitFrame(fd, direction, frame);
  }
}

function looksPlainLsx(u8) {
  // <LSX> = 3c4c53583e
  if (u8.length < 5) return false;
  return (
    u8[0] === 0x3c &&
    u8[1] === 0x4c &&
    u8[2] === 0x53 &&
    u8[3] === 0x58 &&
    u8[4] === 0x3e
  );
}

function looksHexAscii(u8) {
  // exclude trailing NUL for check
  const n = u8.length > 0 && u8[u8.length - 1] === 0 ? u8.length - 1 : u8.length;
  if (n < 32 || n % 2 !== 0) return false;
  for (let i = 0; i < n; i++) {
    const c = u8[i];
    const ok =
      (c >= 0x30 && c <= 0x39) ||
      (c >= 0x61 && c <= 0x66) ||
      (c >= 0x41 && c <= 0x46);
    if (!ok) return false;
  }
  return true;
}

function u8ToAscii(u8, dropNul) {
  let s = "";
  const n = dropNul && u8.length > 0 && u8[u8.length - 1] === 0 ? u8.length - 1 : u8.length;
  for (let i = 0; i < n; i++) {
    const c = u8[i];
    s += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : ".";
  }
  return s;
}

function emitFrame(fd, direction, frameInclNul) {
  frameSeq++;
  const hasNul = frameInclNul.length > 0 && frameInclNul[frameInclNul.length - 1] === 0;
  const s = socks[fd] || {};
  const phase = looksPlainLsx(frameInclNul)
    ? "HANDSHAKE"
    : looksHexAscii(frameInclNul)
      ? "ENCRYPTED"
      : "UNKNOWN";
  const dirTag =
    direction === "out"
      ? s.role === "fdFifa-client-to-4216" || (s.origin === "connect" && s.port === LSX_PORT)
        ? "FIFA_TO_STP"
        : s.origin === "accept"
          ? "STP_TO_FIFA"
          : "OUT"
      : s.origin === "accept"
        ? "FIFA_TO_STP"
        : s.origin === "connect"
          ? "STP_TO_FIFA"
          : "IN";

  // Refine: on accepted server fd, send=STP→FIFA, recv=FIFA→STP
  let flow = dirTag;
  if (s.origin === "accept") {
    flow = direction === "out" ? "STP_TO_FIFA" : "FIFA_TO_STP";
  } else if (s.origin === "connect" && s.port === LSX_PORT) {
    flow = direction === "out" ? "FIFA_TO_STP" : "STP_TO_FIFA";
  }

  emit(
    "STP4216_FRAME_RAW",
    "seq=" +
      frameSeq +
      " fd=" +
      fd +
      " flow=" +
      flow +
      " direction=" +
      direction +
      " role=" +
      (s.role || "?") +
      " len=" +
      frameInclNul.length +
      " nul=" +
      (hasNul ? 1 : 0) +
      " phase=" +
      phase +
      " t=" +
      ts() +
      " hex=" +
      bytesToHex(frameInclNul),
  );

  if (phase === "HANDSHAKE") {
    const xml = u8ToAscii(frameInclNul, true);
    emit(
      "STP4216_HANDSHAKE",
      "seq=" +
        frameSeq +
        " fd=" +
        fd +
        " flow=" +
        flow +
        " xml=" +
        JSON.stringify(xml),
    );
    if (flow === "STP_TO_FIFA" || flow === "FIFA_TO_STP") {
      emit(
        flow === "STP_TO_FIFA" ? "STP4216_PLAIN_OUT" : "STP4216_PLAIN_IN",
        "seq=" +
          frameSeq +
          " fd=" +
          fd +
          " flow=" +
          flow +
          " xml=" +
          JSON.stringify(xml),
      );
    }
  } else if (phase === "ENCRYPTED") {
    const hx = u8ToAscii(frameInclNul, true);
    emit(
      flow === "STP_TO_FIFA" || direction === "out"
        ? "STP4216_CIPHER_OUT"
        : "STP4216_CIPHER_IN",
      "seq=" +
        frameSeq +
        " fd=" +
        fd +
        " flow=" +
        flow +
        " hexAscii=" +
        hx,
    );
  }
}

function roleEmit(fd, extra) {
  const s = socks[fd] || {};
  emit(
    "STP4216_SOCKET",
    "fd=" +
      fd +
      " local=" +
      (s.local || "?") +
      " peer=" +
      (s.peer || "?") +
      " origin=" +
      (s.origin || "?") +
      " role=" +
      (s.role || "?") +
      " port=" +
      (s.port != null ? s.port : -1) +
      (extra ? " " + extra : ""),
  );
}

function refreshDll() {
  const mods = Process.enumerateModules();
  for (let i = 0; i < mods.length; i++) {
    if ((mods[i].name || "").toLowerCase() === DLL_NAME.toLowerCase()) {
      dllMod = {
        base: mods[i].base,
        size: mods[i].size,
        path: mods[i].path || "",
      };
      return true;
    }
  }
  return false;
}

function scanDllStrings() {
  if (!dllMod) return;
  const needles = [
    "GetConfigResponse",
    "GetInternetConnectedState",
    "InternetConnectedState",
    "LoginEvent",
    "LOGIN_EVENT",
    "OnlineStatusEvent",
    "GetProfileResponse",
    "AuthCode",
    "EALS",
    "EbisuSDK",
    "Utility",
    "XMPP",
    "Facility",
    "ContentId",
    "MultiplayerId",
  ];
  try {
    const ranges = [{ base: dllMod.base, size: dllMod.size }];
    for (let n = 0; n < needles.length; n++) {
      const needle = needles[n];
      let hits = 0;
      try {
        const pattern = needle
          .split("")
          .map(function (c) {
            return ("0" + c.charCodeAt(0).toString(16)).slice(-2);
          })
          .join(" ");
        const res = Memory.scanSync(dllMod.base, dllMod.size, pattern);
        hits = res.length;
      } catch (e) {}
      emit("STP4216_DLL_STRING", "needle=" + needle + " hits=" + hits);
    }
  } catch (e) {
    emit("STP4216_DLL_STRING", "scan-fail " + e);
  }
}

function hookLoad() {
  const apis = [
    ["LoadLibraryExW", true],
    ["LoadLibraryW", true],
    ["LoadLibraryA", false],
    ["LoadLibraryExA", false],
  ];
  for (let i = 0; i < apis.length; i++) {
    const name = apis[i][0];
    const wide = apis[i][1];
    const addr = resolveExport("kernel32.dll", name);
    if (!addr) continue;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        try {
          const p = wide ? args[0].readUtf16String(512) : args[0].readAnsiString(512);
          this.hit = /stp-origin_emu/i.test(p || "");
        } catch (e) {
          this.hit = false;
        }
      },
      onLeave: function (retval) {
        if (!this.hit) return;
        setTimeout(function () {
          if (refreshDll()) {
            emit(
              "STP4216_SOCKET",
              "dll-loaded base=" + dllMod.base + " size=0x" + dllMod.size.toString(16),
            );
            setTimeout(scanDllStrings, 500);
          }
        }, 20);
      },
    });
  }
}

function hookNet() {
  function attach(api, kind) {
    const addr = resolveExport("ws2_32.dll", api);
    if (!addr) return;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        this.fd = args[0].toInt32();
        this.from = callerInDll(this.context);
        if (kind === "bind" || kind === "connect") this.info = sockaddrInfo(args[1]);
        if (kind === "send" || kind === "recv") {
          this.buf = args[1];
          this.len = args[2].toInt32();
        }
      },
      onLeave: function (retval) {
        const fd = this.fd;
        if (kind === "bind") {
          const info = this.info;
          socks[fd] = {
            origin: "bind",
            role: info.port === LSX_PORT ? "lsx-listen-4216" : "bind-other",
            local: info.ip + ":" + info.port,
            peer: "-",
            port: info.port,
          };
          if (info.port === LSX_PORT) listenFd = fd;
          roleEmit(fd, "api=bind ret=" + retval.toInt32() + (this.from ? " moduleCaller=" + this.from : ""));
        } else if (kind === "listen") {
          if (socks[fd]) roleEmit(fd, "api=listen ret=" + retval.toInt32());
        } else if (kind === "accept") {
          const newFd = retval.toInt32();
          if (newFd < 0) return;
          const local = querySock(newFd, false);
          const peer = querySock(newFd, true);
          socks[newFd] = {
            origin: "accept",
            role: "fdFifa-accepted-on-4216",
            local: local.ip + ":" + local.port,
            peer: peer.ip + ":" + peer.port,
            port: LSX_PORT,
            parentListen: fd,
          };
          roleEmit(newFd, "api=accept listenFd=" + fd + (this.from ? " moduleCaller=" + this.from : ""));
        } else if (kind === "connect") {
          const info = this.info;
          const local = querySock(fd, false);
          let role = "connect-other";
          if (info.port === LSX_PORT) role = "fdFifa-client-to-4216";
          else if (info.port === 3216 || info.port === 3215 || info.port === 3217)
            role = "fdRelay-origin-" + info.port;
          socks[fd] = {
            origin: "connect",
            role: role,
            local: local.ip + ":" + local.port,
            peer: info.ip + ":" + info.port,
            port: info.port,
          };
          roleEmit(fd, "api=connect ret=" + retval.toInt32() + (this.from ? " moduleCaller=" + this.from : ""));
        } else if (kind === "send" || kind === "recv") {
          const n = retval.toInt32();
          if (n <= 0) return;
          if (!isTrackedFd(fd) && !this.from) return;
          if (!isTrackedFd(fd) && this.from) {
            // late-bind tracking for dll traffic
            socks[fd] = socks[fd] || {
              origin: "dll-xfer",
              role: "dll-untyped",
              port: -1,
            };
          }
          const chunk = readBytes(this.buf, n);
          if (kind === "send") appendAndSplit(txBuf, fd, chunk, "out");
          else appendAndSplit(rxBuf, fd, chunk, "in");
        }
      },
    });
    console.log("[stp4216] hooked " + api);
  }
  attach("bind", "bind");
  attach("listen", "listen");
  attach("accept", "accept");
  attach("connect", "connect");
  attach("send", "send");
  attach("recv", "recv");
}

function dumpLaunchEnv() {
  try {
    const keys = [
      "EALsxPort",
      "EALaunchEnv",
      "EALaunchUserAuthToken",
      "EALicenseToken",
      "EAGenericAuthToken",
      "ORIGIN_CONTENT_ID",
      "EADesktop",
    ];
    // Frida: Process.getEnvironment or Module - use kernel32 GetEnvironmentStringsW
    let found = 0;
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      let v = null;
      try {
        // Frida 16+ 
        if (typeof Process.getEnvironmentVariable === "function") {
          v = Process.getEnvironmentVariable(k);
        }
      } catch (e) {}
      if (v == null) {
        try {
          const g = resolveExport("kernel32.dll", "GetEnvironmentVariableW");
          if (g) {
            const fn = new NativeFunction(g, "uint", ["pointer", "pointer", "uint"]);
            const name = Memory.allocUtf16String(k);
            const buf = Memory.alloc(1024);
            const n = fn(name, buf, 512);
            if (n > 0) v = buf.readUtf16String(n);
          }
        } catch (e) {}
      }
      if (v != null && v !== "") {
        found++;
        const redacted =
          /Token|Auth/i.test(k) && v.length > 12
            ? v.slice(0, 6) + "…" + v.slice(-4) + " len=" + v.length
            : v;
        emit("STP4216_LAUNCH_ENV", "key=" + k + " value=" + JSON.stringify(redacted));
      } else {
        emit("STP4216_LAUNCH_ENV", "key=" + k + " value=MISSING");
      }
    }
    emit("STP4216_LAUNCH_ENV", "summary found=" + found + "/" + keys.length);
  } catch (e) {
    emit("STP4216_LAUNCH_ENV", "dump-fail " + e);
  }
}

function hookOnlineCorr() {
  try {
    const base = Process.getModuleByName("FIFA17.exe").base;
    Interceptor.attach(base.add(0x70da3b0), {
      onEnter: function () {
        emit("STP4216_CALLBACK_CORR", "OriginCheckOnline ENTER t=" + ts());
      },
      onLeave: function (retval) {
        onlineSeen = "ret32=0x" + (retval.toInt32() >>> 0).toString(16);
        emit(
          "STP4216_CALLBACK_CORR",
          "OriginCheckOnline LEAVE " + onlineSeen + " t=" + ts(),
        );
        emit(
          "STP4216_LOGIN_EVENT_CORR",
          "OriginCheckOnline " + onlineSeen + " t=" + ts(),
        );
      },
    });
    Interceptor.attach(base.add(0x71b58e0), {
      onEnter: function (args) {
        this.obj = args[0];
      },
      onLeave: function (retval) {
        const r = retval.toInt32();
        let msg = "";
        try {
          // Login obj+0x80 often holds error string ptr (prior TXT_NOT_LOGIN_TO_EBISU)
          const p = this.obj.add(0x80).readPointer();
          if (!p.isNull()) msg = p.readUtf8String(80) || "";
        } catch (e) {}
        if (r !== 6 && r !== 5 && msg.indexOf("TXT_NOT_LOGIN") < 0) return;
        emit(
          "STP4216_CALLBACK_CORR",
          "LoginStateLogin leave ret=" +
            r +
            " onlineSeen=" +
            onlineSeen +
            " msg80=" +
            JSON.stringify(msg) +
            " frames=" +
            frameSeq +
            " t=" +
            ts(),
        );
        emit(
          "STP4216_LOGIN_EVENT_CORR",
          "LoginStateLogin ret=" +
            r +
            " txt=" +
            JSON.stringify(msg) +
            " t=" +
            ts(),
        );
      },
    });
    // LoginStateLoginComplete @ RVA 0x71b6c50
    Interceptor.attach(base.add(0x71b6c50), {
      onEnter: function () {
        emit(
          "STP4216_LOGIN_EVENT_CORR",
          "LoginStateLoginComplete ENTER t=" + ts() + " ★COMPLETE",
        );
      },
    });
    console.log("[stp4216] hooked OriginCheckOnline + LoginStateLogin + LoginComplete");
  } catch (e) {
    console.log("[stp4216] corr hooks skip " + e);
  }
}

function armVerdict() {
  setTimeout(function () {
    emit(
      "STP4216_VERDICT",
      "frames=" +
        frameSeq +
        " onlineSeen=" +
        onlineSeen +
        " listenFd=" +
        listenFd +
        " tags=[" +
        firstHits.slice(0, 20).join(",") +
        "]",
    );
  }, 120000);
}

console.log("[stp4216] STP4216_LOGIN_EVENT / CONTRACT transcript armed mode=" + MODE);
emit("STP4216_SOCKET", "script-start pid=" + Process.id);
dumpLaunchEnv();
if (refreshDll()) emit("STP4216_SOCKET", "dll-already base=" + dllMod.base);
hookLoad();
hookNet();
hookOnlineCorr();
armVerdict();
