/**
 * STP_LSX_PLAIN — observe LSX on :4216 with socket roles + plaintext chronology.
 * Wire decrypt of post-handshake AES is done in Python (lsx_crypto.py).
 * No pokes.
 *
 * Tags:
 *   STP_SOCKET_ROLE
 *   STP_LSX_PLAIN_OUT / STP_LSX_CIPHER_OUT
 *   STP_LSX_CIPHER_IN / STP_LSX_PLAIN_IN   (PLAIN_IN also via memcpy)
 *   STP_LSX_MESSAGE
 *   STP_CALLBACK_ENTER / STP_ONLINE_VALUE / STP_AUTHCODE_VALUE
 *   STP_OUTFLAGS_CORR / STP_VERDICT
 */
"use strict";

const MODE = (typeof STP_OBS_MODE !== "undefined" ? STP_OBS_MODE : "LSX_PLAIN").toString();
const DLL_NAME = "stp-origin_emu.dll";
const LSX_PORT = 4216;

let dllMod = null;
const socks = {}; // fd -> { role, local, peer, origin, listenPort }
let listenFd = -1;
let msgCount = 0;
let plainOut = 0;
let plainIn = 0;
let cipherOut = 0;
let cipherIn = 0;
let onlineSeen = null;
const firstHits = [];
const hookedExp = {};

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
  if (firstHits.length < 120) firstHits.push(tag + ":" + msg.slice(0, 80));
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
    for (let i = 0; i < Math.min(bt.length, 10); i++) {
      if (inDll(bt[i])) return bt[i].toString();
    }
  } catch (e) {}
  return null;
}

function btShort(ctx) {
  try {
    const bt = Thread.backtrace(ctx, Backtracer.ACCURATE);
    const parts = [];
    for (let i = 0; i < Math.min(bt.length, 6); i++) {
      const a = bt[i];
      let sym = "";
      try {
        const s = DebugSymbol.fromAddress(a);
        if (s && s.name) sym = s.name;
      } catch (e) {}
      parts.push(a + (sym ? "(" + sym + ")" : ""));
    }
    return parts.join(" < ");
  } catch (e) {
    return "";
  }
}

function readUtf16(p, n) {
  try {
    return p && !p.isNull() ? p.readUtf16String(n || 260) || "" : "";
  } catch (e) {
    return "";
  }
}
function readAnsi(p, n) {
  try {
    return p && !p.isNull() ? p.readAnsiString(n || 260) || "" : "";
  } catch (e) {
    return "";
  }
}

function sockaddrInfo(sa) {
  try {
    if (!sa || sa.isNull()) return { ip: "?", port: -1 };
    if (sa.readU16() !== 2) return { ip: "fam", port: -1 };
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

function querySockName(fd, peer) {
  const api = peer ? "getpeername" : "getsockname";
  const fn = resolveExport("ws2_32.dll", api);
  if (!fn) return { ip: "?", port: -1 };
  const getname = new NativeFunction(fn, "int", ["int", "pointer", "pointer"]);
  const sa = Memory.alloc(28);
  const len = Memory.alloc(4);
  len.writeU32(28);
  const r = getname(fd, sa, len);
  if (r !== 0) return { ip: "?", port: -1 };
  return sockaddrInfo(sa);
}

function roleEmit(fd, extra) {
  const s = socks[fd] || {};
  emit(
    "STP_SOCKET_ROLE",
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
      " listenPort=" +
      (s.listenPort != null ? s.listenPort : -1) +
      (extra ? " " + extra : ""),
  );
}

function classifyBuf(ptrBuf, n) {
  if (!ptrBuf || ptrBuf.isNull() || n <= 0) return { kind: "empty", text: "" };
  const take = Math.min(n, 8192);
  let bytes;
  try {
    bytes = new Uint8Array(ptrBuf.readByteArray(take));
  } catch (e) {
    return { kind: "err", text: "" };
  }
  let text = "";
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i];
    if (c === 0) break;
    text += c >= 0x20 && c < 0x7f ? String.fromCharCode(c) : ".";
  }
  if (text.indexOf("<LSX>") === 0 || text.indexOf("<?xml") === 0) {
    // full xml up to n
    let full = "";
    try {
      full = ptrBuf.readUtf8String(Math.min(n, 65536)) || text;
    } catch (e) {
      full = text;
    }
    return { kind: "plain", text: full };
  }
  // hex-ascii ciphertext (LSX post-handshake)
  let hexOnly = true;
  let hexLen = 0;
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i];
    if (c === 0 || c === 10 || c === 13) break;
    const ok =
      (c >= 0x30 && c <= 0x39) ||
      (c >= 0x61 && c <= 0x66) ||
      (c >= 0x41 && c <= 0x46);
    if (!ok) {
      hexOnly = false;
      break;
    }
    hexLen++;
  }
  if (hexOnly && hexLen >= 32 && hexLen % 2 === 0) {
    return { kind: "cipher_hex", text: text.slice(0, hexLen) };
  }
  return { kind: "bin", text: text.slice(0, 64) };
}

function parseLsxMessage(xml, direction, fd) {
  msgCount++;
  let type = "?";
  let requestId = "";
  let source = "";
  let responseTo = "";
  try {
    let m = /<(Challenge|ChallengeResponse|ChallengeAccepted|Request|Response|Event)\b/.exec(
      xml,
    );
    if (m) type = m[1];
    m = /\bid="(\d+)"/.exec(xml);
    if (m) requestId = m[1];
    m = /\bsender="([^"]+)"/.exec(xml);
    if (m) source = m[1];
    m = /\brecipient="([^"]+)"/.exec(xml);
    if (m) source = source || m[1];
    // inner command name
    m =
      /<(Get[A-Za-z0-9]+|Login|GoOnline|Query[A-Za-z0-9]+|GetInternetConnectedState|GetAuthCode|GetAuthToken|GetProfile|GetPresence)\b/.exec(
        xml,
      );
    if (m) type = type + "/" + m[1];
    else {
      m = /<(Get[A-Za-z0-9]+|Login|GoOnline|Query[A-Za-z0-9]+)\b/.exec(xml);
      if (m) type = type + "/" + m[1];
    }
  } catch (e) {}
  emit(
    "STP_LSX_MESSAGE",
    "type=" +
      type +
      " requestId=" +
      requestId +
      " source=" +
      source +
      " responseTo=" +
      responseTo +
      " dir=" +
      direction +
      " fd=" +
      fd +
      " len=" +
      xml.length +
      " t=" +
      ts(),
  );
  // extract interesting values
  try {
    let m = /connected="([^"]+)"/i.exec(xml);
    if (m) emit("STP_ONLINE_VALUE", "from=lsx xml connected=" + m[1] + " t=" + ts());
    m = /Online="([^"]+)"/i.exec(xml);
    if (m) emit("STP_ONLINE_VALUE", "from=lsx xml Online=" + m[1] + " t=" + ts());
    m = /AuthCode="([^"]+)"/i.exec(xml);
    if (m) emit("STP_AUTHCODE_VALUE", "AuthCode=" + m[1]);
    m = /authCode="([^"]+)"/i.exec(xml);
    if (m) emit("STP_AUTHCODE_VALUE", "authCode=" + m[1]);
    m = /Persona[Nn]ame="([^"]+)"/.exec(xml);
    if (m) emit("STP_PROFILE_VALUE", "PersonaName=" + m[1]);
    m = /UserId="([^"]+)"/.exec(xml);
    if (m) emit("STP_PROFILE_VALUE", "UserId=" + m[1]);
  } catch (e) {}
}

function onPayload(direction, fd, ptrBuf, n, ctx) {
  const c = classifyBuf(ptrBuf, n);
  const thr = Process.getCurrentThreadId();
  const fromDll = callerInDll(ctx);
  const role = (socks[fd] && socks[fd].role) || "?";
  if (c.kind === "plain") {
    if (direction === "out") {
      plainOut++;
      emit(
        "STP_LSX_PLAIN_OUT",
        "fd=" +
          fd +
          " role=" +
          role +
          " len=" +
          n +
          " thread=" +
          thr +
          " t=" +
          ts() +
          (fromDll ? " callerDll=" + fromDll : "") +
          " xml=" +
          JSON.stringify(c.text),
      );
    } else {
      plainIn++;
      emit(
        "STP_LSX_PLAIN_IN",
        "fd=" +
          fd +
          " role=" +
          role +
          " len=" +
          n +
          " thread=" +
          thr +
          " t=" +
          ts() +
          (fromDll ? " callerDll=" + fromDll : "") +
          " xml=" +
          JSON.stringify(c.text),
      );
    }
    parseLsxMessage(c.text, direction, fd);
    emit(
      "STP_LSX_BT",
      "dir=" + direction + " fd=" + fd + " bt=" + btShort(ctx),
    );
  } else if (c.kind === "cipher_hex") {
    if (direction === "out") {
      cipherOut++;
      emit(
        "STP_LSX_CIPHER_OUT",
        "fd=" +
          fd +
          " role=" +
          role +
          " len=" +
          c.text.length +
          " thread=" +
          thr +
          " t=" +
          ts() +
          " hex=" +
          c.text,
      );
    } else {
      cipherIn++;
      emit(
        "STP_LSX_CIPHER_IN",
        "fd=" +
          fd +
          " role=" +
          role +
          " len=" +
          c.text.length +
          " thread=" +
          thr +
          " t=" +
          ts() +
          " hex=" +
          c.text,
      );
    }
  }
}

function refreshDll() {
  const mods = Process.enumerateModules();
  for (let i = 0; i < mods.length; i++) {
    if ((mods[i].name || "").toLowerCase() === DLL_NAME.toLowerCase()) {
      dllMod = {
        name: mods[i].name,
        base: mods[i].base,
        size: mods[i].size,
        path: mods[i].path || "",
      };
      return true;
    }
  }
  return false;
}

function hookDllInit() {
  if (!dllMod) return;
  try {
    const m = Process.getModuleByName(DLL_NAME);
    const di = m.findExportByName
      ? m.findExportByName("DllInit")
      : m.getExportByName
        ? m.getExportByName("DllInit")
        : null;
    if (!di || hookedExp.DllInit) return;
    hookedExp.DllInit = true;
    Interceptor.attach(di, {
      onEnter: function (args) {
        emit(
          "STP_CALLBACK_ENTER",
          "DllInit a0=" +
            args[0] +
            " a1=" +
            args[1] +
            " a2=" +
            args[2] +
            " a3=" +
            args[3] +
            " bt=" +
            btShort(this.context),
        );
      },
      onLeave: function (retval) {
        emit("STP_CALLBACK_ENTER", "DllInit LEAVE ret=" + retval);
      },
    });
    console.log("[stp] hooked DllInit");
  } catch (e) {
    console.log("[stp] DllInit hook fail " + e);
  }
}

function hookLoad() {
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
        this.hit = /stp-origin_emu/i.test(
          wide ? readUtf16(args[0], 512) : readAnsi(args[0], 512),
        );
      },
      onLeave: function (retval) {
        if (!this.hit) return;
        setTimeout(function () {
          if (refreshDll()) {
            emit(
              "STP_SOCKET_ROLE",
              "dll-loaded base=" +
                dllMod.base +
                " size=0x" +
                dllMod.size.toString(16),
            );
            hookDllInit();
            hookMemcpyPlain();
          }
        }, 30);
      },
    });
  }
}

let memcpyHooked = false;
function hookMemcpyPlain() {
  if (memcpyHooked) return;
  const names = [
    ["ucrtbase.dll", "memcpy"],
    ["msvcrt.dll", "memcpy"],
    ["ntdll.dll", "memcpy"],
  ];
  for (let i = 0; i < names.length; i++) {
    const addr = resolveExport(names[i][0], names[i][1]);
    if (!addr) continue;
    memcpyHooked = true;
    Interceptor.attach(addr, {
      onEnter: function (args) {
        if (!dllMod) return;
        const from = callerInDll(this.context);
        if (!from) return;
        const n = args[2].toInt32();
        if (n < 12 || n > 200000) return;
        const kind = classifyBuf(args[1], Math.min(n, 64));
        if (kind.kind !== "plain") return;
        const full = classifyBuf(args[1], n);
        plainIn++;
        emit(
          "STP_LSX_PLAIN_IN",
          "via=memcpy dst=" +
            args[0] +
            " len=" +
            n +
            " callerDll=" +
            from +
            " t=" +
            ts() +
            " xml=" +
            JSON.stringify(full.text),
        );
        parseLsxMessage(full.text, "memcpy", -1);
      },
    });
    console.log("[stp] hooked memcpy @" + names[i][0]);
    break;
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
        if (kind === "bind" || kind === "connect") {
          this.info = sockaddrInfo(args[1]);
        }
        if (kind === "send" || kind === "recv") {
          this.buf = args[1];
          this.len = args[2].toInt32();
        }
      },
      onLeave: function (retval) {
        const fd = this.fd;
        if (kind === "bind") {
          const info = this.info;
          socks[fd] = socks[fd] || {};
          socks[fd].origin = "bind";
          socks[fd].local = info.ip + ":" + info.port;
          socks[fd].listenPort = info.port;
          socks[fd].role = info.port === LSX_PORT ? "lsx-listen" : "bind-other";
          if (info.port === LSX_PORT) listenFd = fd;
          roleEmit(fd, "api=bind ret=" + retval.toInt32() + (this.from ? " moduleCaller=" + this.from : ""));
        } else if (kind === "listen") {
          socks[fd] = socks[fd] || {};
          socks[fd].origin = "listen";
          roleEmit(fd, "api=listen ret=" + retval.toInt32() + (this.from ? " moduleCaller=" + this.from : ""));
        } else if (kind === "accept") {
          const newFd = retval.toInt32();
          if (newFd < 0) return;
          const local = querySockName(newFd, false);
          const peer = querySockName(newFd, true);
          socks[newFd] = {
            origin: "accept",
            role: "fdFifa-accepted-on-4216",
            local: local.ip + ":" + local.port,
            peer: peer.ip + ":" + peer.port,
            listenPort: LSX_PORT,
            parentListen: fd,
          };
          roleEmit(
            newFd,
            "api=accept listenFd=" +
              fd +
              " ret=" +
              newFd +
              (this.from ? " moduleCaller=" + this.from : ""),
          );
        } else if (kind === "connect") {
          const info = this.info;
          const local = querySockName(fd, false);
          const peer = { ip: info.ip, port: info.port };
          let role = "connect-other";
          if (info.port === LSX_PORT) {
            role = "fdClient-connect-4216";
            // Same-process self-connect to DLL listener = FIFA LSX client end
            if (listenFd >= 0) role = "fdFifa-client-to-4216";
          } else if (info.port === 3216 || info.port === 3215 || info.port === 3217) {
            role = "fdRelay-origin-" + info.port;
          }
          socks[fd] = {
            origin: "connect",
            role: role,
            local: local.ip + ":" + local.port,
            peer: peer.ip + ":" + peer.port,
            listenPort: info.port,
          };
          roleEmit(
            fd,
            "api=connect ret=" +
              retval.toInt32() +
              (this.from ? " moduleCaller=" + this.from : ""),
          );
          if (info.port === LSX_PORT) {
            emit(
              "STP_CONNECT_4216",
              "fd=" + fd + " role=" + role + " ret=" + retval.toInt32(),
            );
          }
        } else if (kind === "send" || kind === "recv") {
          const n = retval.toInt32();
          if (n <= 0) return;
          const s = socks[fd];
          const track =
            (s && (s.listenPort === LSX_PORT || (s.role || "").indexOf("4216") >= 0 || (s.role || "").indexOf("Fifa") >= 0 || (s.role || "").indexOf("Relay") >= 0)) ||
            (s && s.parentListen === listenFd) ||
            !!this.from;
          if (!track && !(s && s.role)) {
            // also track if we know fd from accept/connect to 4216
            if (!s) return;
          }
          if (!track && !(s && ("" + s.role).indexOf("4216") >= 0) && !(s && ("" + s.role).indexOf("Fifa") >= 0) && !(s && ("" + s.role).indexOf("lsx") >= 0) && !(s && ("" + s.role).indexOf("Relay") >= 0)) {
            if (!this.from) return;
          }
          onPayload(kind === "send" ? "out" : "in", fd, this.buf, n, this.context);
        }
      },
    });
    console.log("[stp] hooked " + api);
  }
  attach("bind", "bind");
  attach("listen", "listen");
  attach("accept", "accept");
  attach("connect", "connect");
  attach("WSAConnect", "connect");
  attach("send", "send");
  attach("recv", "recv");
}

function hookOriginOnline() {
  // FIFA17.exe RVA from prior sessions
  const rva = 0x70da3b0;
  try {
    const base = Process.getModuleByName("FIFA17.exe").base;
    const addr = base.add(rva);
    Interceptor.attach(addr, {
      onEnter: function (args) {
        emit(
          "STP_CALLBACK_ENTER",
          "OriginCheckOnlineWrapper a0=" +
            args[0] +
            " a1=" +
            args[1] +
            " t=" +
            ts(),
        );
      },
      onLeave: function (retval) {
        let online = "?";
        try {
          // prior obs: online flag often near wrapper — scan args not reliable
          online = "ret=" + retval + " ret32=0x" + (retval.toInt32() >>> 0).toString(16);
        } catch (e) {}
        onlineSeen = online;
        emit("STP_ONLINE_VALUE", "from=OriginCheckOnlineWrapper " + online + " t=" + ts());
      },
    });
    console.log("[stp] hooked OriginCheckOnlineWrapper @" + addr);
  } catch (e) {
    console.log("[stp] OriginCheckOnline hook skip " + e);
  }

  // LoginStateLogin leave — light corr
  try {
    const base = Process.getModuleByName("FIFA17.exe").base;
    const login = base.add(0x71b58e0);
    Interceptor.attach(login, {
      onLeave: function (retval) {
        const r = retval.toInt32();
        if (r !== 6 && r !== 5) return;
        emit(
          "STP_OUTFLAGS_CORR",
          "LoginStateLogin leave ret=" +
            r +
            " onlineSeen=" +
            onlineSeen +
            " plainOut=" +
            plainOut +
            " plainIn=" +
            plainIn +
            " cipherOut=" +
            cipherOut +
            " cipherIn=" +
            cipherIn +
            " t=" +
            ts(),
        );
      },
    });
    console.log("[stp] hooked LoginStateLogin @" + login);
  } catch (e) {}
}

function armVerdict() {
  setTimeout(function () {
    let verdict = "INCOMPLETE";
    if (plainOut + plainIn > 3 && cipherOut + cipherIn > 0) {
      verdict = "HANDSHAKE_PLUS_CIPHER";
    }
    if (onlineSeen) verdict += "+ONLINE_OBS";
    emit(
      "STP_VERDICT",
      "verdict=" +
        verdict +
        " plainOut=" +
        plainOut +
        " plainIn=" +
        plainIn +
        " cipherOut=" +
        cipherOut +
        " cipherIn=" +
        cipherIn +
        " msgCount=" +
        msgCount +
        " onlineSeen=" +
        onlineSeen +
        " first=[" +
        firstHits.slice(0, 12).join(" || ") +
        "]",
    );
  }, 100000);
}

console.log("[stp] STP_LSX_PLAIN armed mode=" + MODE);
emit("STP_SOCKET_ROLE", "script-start pid=" + Process.id);
if (refreshDll()) {
  hookDllInit();
  hookMemcpyPlain();
}
hookLoad();
hookNet();
hookOriginOnline();
armVerdict();
