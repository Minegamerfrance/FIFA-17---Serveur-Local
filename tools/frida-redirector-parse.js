/**
 * FIFA 17 — Redirector XML parse autopsy (v74b-REDIR)
 *
 * Fix vs v74:
 * - Full SSL sticky bypass (LIVE + flag+288 + softHost) — v74 cut before XML
 * - Xref scan without trailing ?? wildcards
 * - Hook Heat2 / ServerInstanceInfo / getServerInstance
 */
"use strict";

const VERSION = "v74c-REDIR";
const CERT_CN = "gosredirector.ea.com";
const PORTS = [42230, 42127, 10041];
const FLAG_OFF = 288;
const ISTATE_OFF = 272;
const PSECURE_OFF = 280;
const RVA_FAIL_9 = 0x61326fa;
const RVA_JE1 = 0x612f39c;
const RVA_JE2 = 0x61261eb;
const RVA_PARENT = 0x612d4c0;

let redirectorFd = -1;

const INVENTORY = [
  "getServerInstance",
  "ServerInstanceInfo",
  "standardSecure_v4",
  "ProtoHttp",
  "Heat2",
  "Fire2",
  "serverinstancereply",
  "serverinstancerequest",
  "hostnameaddress",
  "ippairaddress",
  "connectionprofile",
  "fifa-2017-pc",
];

const WATCH_RE =
  /serverinstance|getserverinstance|ippair|hostname|xboxclient|nspa|secu|xdns|address|standardsecure|fifa-2017|valu|exip|inip|heat2|fire2|protohttp|blazeerror/i;

let live = null;
let sawClientHello = false;
let flagSet = false;
let setupDone = false;

function log(msg) {
  console.log("[redir-parse] " + msg);
}

function getMod() {
  return Process.getModuleByName("FIFA17.exe");
}

function patchBytes(addr, bytes, label) {
  Memory.protect(addr, bytes.length, "rwx");
  const before = [];
  for (let i = 0; i < 8; i++) before.push(addr.add(i).readU8().toString(16).padStart(2, "0"));
  addr.writeByteArray(bytes);
  log("PATCH " + label + " @" + addr + " was[" + before.join(" ") + "]");
}

function applySslPatches(mod) {
  patchBytes(mod.base.add(RVA_FAIL_9), [0xb8, 0x15, 0x00, 0x00, 0x00], "mov eax,0x15 @ FAIL_9");
  patchBytes(mod.base.add(RVA_JE1), [0xeb], "je->jmp err1");
  patchBytes(mod.base.add(RVA_JE2), [0xeb], "je->jmp err2");
}

function hostNameAt(p) {
  try {
    return p.readUtf8String(128) || "";
  } catch (_) {
    return "";
  }
}

function softHostEnsure(tag) {
  if (!live || !sawClientHello) return;
  try {
    const cur = hostNameAt(live);
    if (cur !== CERT_CN) {
      live.writeUtf8String(CERT_CN);
      log("softHost '" + cur + "' → '" + CERT_CN + "' [" + tag + "]");
    }
  } catch (e) {
    log("softHost err " + e);
  }
}

function setFlagEnsure(tag) {
  if (!live) return;
  try {
    const v = live.add(FLAG_OFF).readU8();
    if (v !== 1) {
      live.add(FLAG_OFF).writeU8(1);
      log("flag +288 " + v + "→1 [" + tag + "]");
    }
    flagSet = true;
  } catch (e) {
    log("flag err " + e);
  }
}

function readPortBE(p) {
  return (p.readU8() << 8) | p.add(1).readU8();
}

function isProtoSSL(addr) {
  try {
    if (addr.add(256).readU16() !== 2) return false;
    if (PORTS.indexOf(readPortBE(addr.add(258))) < 0) return false;
    return true;
  } catch (_) {
    return false;
  }
}

/** v73: ProtoSSL object is sockaddr_in* - 256 on connect. */
function tryAdopt(addr, tag) {
  if (!addr || addr.isNull() || !isProtoSSL(addr)) return false;
  if (live && live.equals(addr)) {
    setFlagEnsure(tag);
    return true;
  }
  live = addr;
  flagSet = false;
  log("★ LIVE @" + addr + " iState=" + addr.add(ISTATE_OFF).readS32() + " [" + tag + "]");
  setFlagEnsure(tag);
  return true;
}

function cstr(p, max) {
  try {
    if (!p || p.isNull()) return null;
    return p.readUtf8String(max || 200);
  } catch (_) {
    return null;
  }
}

function scanAscii(mod, needle) {
  const pattern = needle
    .split("")
    .map((c) => c.charCodeAt(0).toString(16).padStart(2, "0"))
    .join(" ");
  try {
    return Memory.scanSync(mod.base, mod.size, pattern).slice(0, 6).map((h) => h.address);
  } catch (_) {
    return [];
  }
}

function inventoryStrings(mod) {
  log("--- string inventory ---");
  const found = [];
  for (let i = 0; i < INVENTORY.length; i++) {
    const n = INVENTORY[i];
    const hits = scanAscii(mod, n);
    log((hits.length ? "FOUND " : "miss  ") + n + (hits.length ? " x" + hits.length + " @" + hits[0] : ""));
    if (hits.length) found.push({ name: n, addr: hits[0], all: hits });
  }
  log("--- end inventory (" + found.length + "/" + INVENTORY.length + ") ---");
  return found;
}

function hookCrtWatches() {
  const names = ["strstr", "strcmp", "strncmp", "_stricmp", "_strnicmp"];
  for (let i = 0; i < names.length; i++) {
    let addr;
    try {
      addr = Module.getGlobalExportByName(names[i]);
    } catch (_) {
      continue;
    }
    Interceptor.attach(addr, {
      onEnter(args) {
        const a = cstr(args[0], 160);
        const b = cstr(args[1], 160);
        if (!WATCH_RE.test((a || "") + "||" + (b || ""))) return;
        log(
          "CRT " +
            names[i] +
            '("' +
            (a || "").replace(/\r?\n/g, "\\n").slice(0, 100) +
            '", "' +
            (b || "").replace(/\r?\n/g, "\\n").slice(0, 100) +
            '")',
        );
        this.watch = true;
      },
      onLeave(retval) {
        if (this.watch) log("CRT → " + retval);
      },
    });
    log("hooked " + names[i]);
  }
}

function setupSslOnLive(mod, tag) {
  if (setupDone || !live) return;
  setupDone = true;
  softHostEnsure(tag);
  setFlagEnsure(tag);
  applySslPatches(mod);
  log("SSL sticky setup done [" + tag + "]");
}

function hookSockets(mod) {
  const connect = Module.getGlobalExportByName("connect");
  const send = Module.getGlobalExportByName("send");
  const recv = Module.getGlobalExportByName("recv");
  const closesocket = Module.getGlobalExportByName("closesocket");
  const shutdown = Module.getGlobalExportByName("shutdown");

  function portOf(sa) {
    try {
      return (sa.add(2).readU8() << 8) | sa.add(3).readU8();
    } catch (_) {
      return 0;
    }
  }

  Interceptor.attach(connect, {
    onEnter(args) {
      const port = portOf(args[1]);
      this.port = port;
      if (PORTS.indexOf(port) < 0) return;
      try {
        redirectorFd = args[0].toInt32();
      } catch (_) {
        redirectorFd = -1;
      }
      log("connect :" + port + " fd=" + args[0]);
      if (port === 10041) log("★★★ BLAZE PORT 10041 — redirector XML ACCEPTED");
      // Critical: same as v73
      tryAdopt(args[1].sub(256), "connect-sa");
    },
  });

  Interceptor.attach(send, {
    onEnter(args) {
      this._block = false;
      try {
        if (redirectorFd >= 0 && args[0].toInt32() !== redirectorFd) return;
      } catch (_) {}
      const n = args[2].toInt32();
      if (n < 5) return;
      const buf = args[1];
      const head0 = buf.readU8();
      const head1 = buf.add(1).readU8();

      // Block bad_certificate alert so handshake can continue (v73)
      if (head0 === 0x15 && n >= 7) {
        const desc = buf.add(6).readU8();
        if (desc === 42 || desc === 43 || desc === 46) {
          this._block = true;
          args[2] = ptr(0);
          log("blocked alert " + desc);
          return;
        }
        log("ALERT 2/" + desc);
      }

      if (head0 === 0x16 && head1 === 0x03 && n > 40 && n < 200) {
        const hs = buf.add(5).readU8();
        if (hs === 0x01) {
          sawClientHello = true;
          log("ClientHello len=" + n);
          softHostEnsure("after-CH");
          setFlagEnsure("after-CH");
          setupSslOnLive(mod, "after-CH");
        } else if (hs === 0x10) {
          log("★ ClientKeyExchange " + n);
        }
      }
      if (head0 === 0x14) log("★ ChangeCipherSpec " + n);

      const s = cstr(buf, Math.min(n, 24));
      if (s && (s.indexOf("POST") === 0 || s.indexOf("HTTP") === 0 || s.indexOf("<?xml") === 0)) {
        log("★ plaintext TX (" + n + "):\n" + cstr(buf, Math.min(n, 2500)));
      }
    },
  });

  Interceptor.attach(recv, {
    onEnter(args) {
      this.buf = args[1];
      this.fd = -1;
      try {
        this.fd = args[0].toInt32();
      } catch (_) {}
    },
    onLeave(retval) {
      const n = retval.toInt32();
      if (n < 8 || !this.buf) return;
      if (redirectorFd >= 0 && this.fd !== redirectorFd) return;
      softHostEnsure("recv");
      setFlagEnsure("recv");
      const s = cstr(this.buf, Math.min(n, 24));
      if (s && (s.indexOf("HTTP") === 0 || s.indexOf("<?xml") === 0 || s.indexOf("<server") === 0)) {
        log("★ plaintext RX (" + n + "):\n" + cstr(this.buf, Math.min(n, 2500)));
      }
    },
  });

  Interceptor.attach(shutdown, {
    onEnter(args) {
      log("shutdown how=" + args[1] + " live=" + !!live);
    },
  });
  Interceptor.attach(closesocket, {
    onEnter() {
      log("closesocket live=" + !!live);
    },
  });
  log("hooked sockets");
}

function hookParent(mod) {
  const addr = mod.base.add(RVA_PARENT);
  Interceptor.attach(addr, {
    onEnter(args) {
      const p = args[0];
      tryAdopt(p, "PARENT");
      if (live) {
        softHostEnsure("PARENT");
        setFlagEnsure("PARENT");
        if (sawClientHello) setupSslOnLive(mod, "PARENT");
      }
      this.p = p;
    },
    onLeave(retval) {
      try {
        if (!this.p) return;
        const st = this.p.add(ISTATE_OFF).readS32();
        if (st < 30) return;
        for (let off = 0x100; off < 0x500; off += 8) {
          try {
            const q = this.p.add(off).readPointer();
            const s = cstr(q, 48);
            if (!s) continue;
            if (
              s.indexOf("<?xml") === 0 ||
              s.indexOf("HTTP/1") === 0 ||
              s.indexOf("<server") === 0 ||
              s.indexOf("POST ") === 0
            ) {
              log("★ decrypted @" + off.toString(16) + " st=" + st + ":\n" + cstr(q, 2500));
            }
          } catch (_) {}
        }
      } catch (_) {}
    },
  });
  log("hooked PARENT @" + addr);
}

/** LEA r64,[rip+disp32] — pattern without trailing wildcards. */
function findRipLeaXrefs(rangeBase, rangeSize, strAddr, maxHits) {
  const results = [];
  // Cover common ModRM for [rip+disp32]: 05,0d,15,1d,25,2d,35,3d with REX.W 48/4C
  const prefixes = [
    [0x48, 0x8d],
    [0x4c, 0x8d],
  ];
  const modrms = [0x05, 0x0d, 0x15, 0x1d, 0x25, 0x2d, 0x35, 0x3d];

  for (let pi = 0; pi < prefixes.length && results.length < maxHits; pi++) {
    for (let mi = 0; mi < modrms.length && results.length < maxHits; mi++) {
      const pat =
        prefixes[pi][0].toString(16).padStart(2, "0") +
        " " +
        prefixes[pi][1].toString(16).padStart(2, "0") +
        " " +
        modrms[mi].toString(16).padStart(2, "0");
      let hits;
      try {
        hits = Memory.scanSync(rangeBase, rangeSize, pat);
      } catch (e) {
        continue;
      }
      for (let i = 0; i < hits.length && results.length < maxHits; i++) {
        const addr = hits[i].address;
        try {
          const disp = addr.add(3).readS32();
          const target = addr.add(7).add(disp);
          if (target.equals(strAddr)) results.push(addr);
        } catch (_) {}
      }
    }
  }
  return results;
}

function findFnStart(addr) {
  for (let b = 0; b < 0x200; b++) {
    const p = addr.sub(b);
    try {
      const v = p.readU8();
      if (v === 0xcc && b > 4) return p.add(1);
      if (v === 0x40 && p.add(1).readU8() === 0x55) return p;
      if (v === 0x55 && p.add(1).readU8() === 0x48) return p;
    } catch (_) {
      break;
    }
  }
  return addr;
}

function hookKeyXrefs(mod, found) {
  const want = found.filter((f) =>
    /getServerInstance|ServerInstanceInfo|Heat2|Fire2|ProtoHttp/i.test(f.name),
  );
  const ranges = mod.enumerateRanges("r-x");
  if (!ranges.length || !want.length) {
    log("xref: nothing to hook");
    return;
  }
  const range = ranges[0];
  const size = Math.min(range.size, 16 * 1024 * 1024);
  log("xref scan " + range.base + " +" + size + " keys=" + want.length);

  const seen = {};
  let hooked = 0;

  for (let wi = 0; wi < want.length; wi++) {
    const name = want[wi].name;
    const strAddr = want[wi].addr;
    const xrefs = findRipLeaXrefs(range.base, size, strAddr, 5);
    log("xref " + name + " LEAs=" + xrefs.length);
    for (let xi = 0; xi < xrefs.length; xi++) {
      const fn = findFnStart(xrefs[xi]);
      const key = fn.toString();
      if (seen[key]) continue;
      seen[key] = true;
      try {
        Interceptor.attach(fn, {
          onEnter(args) {
            const parts = [];
            for (let ai = 0; ai < 4; ai++) {
              const s = cstr(args[ai], 100);
              parts.push(
                s
                  ? "a" + ai + '="' + s.replace(/\r?\n/g, "\\n").slice(0, 90) + '"'
                  : "a" + ai + "=" + args[ai],
              );
            }
            log("CALL " + name + " @" + fn + " " + parts.join(" "));
          },
          onLeave(retval) {
            log("RET  " + name + " @" + fn + " → " + retval);
          },
        });
        log("hooked " + name + " fn@" + fn);
        hooked++;
      } catch (e) {
        log("hook fail " + name + ": " + e);
      }
    }
  }
  log("xref hooks=" + hooked);
}

function main() {
  const mod = getMod();
  log("loaded " + VERSION + " base=" + mod.base + " size=0x" + mod.size.toString(16));

  // Patches applied again after CH when LIVE is known; also apply now as baseline
  applySslPatches(mod);
  hookSockets(mod);
  hookParent(mod);
  hookCrtWatches();

  const found = inventoryStrings(mod);
  hookKeyXrefs(mod, found);

  log("READY — npm up → FIFA → ce script → UT (attends l'erreur complète)");
  log("Succès = ★★★ BLAZE PORT 10041");
  log("Sinon envoie CALL/RET/CRT + softHost/flag");
}

main();
