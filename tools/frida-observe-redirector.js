/**
 * OBSERVE-ONLY: capture what FIFA 17 asks / sees for Redirector.
 * Does NOT invent reply formats — dumps:
 *  - plaintext HTTP buffers (request + any reply fragments in memory)
 *  - XmlDecoder / Heat2 unknown-member errors
 *  - post-redir connects
 *  - presence of reply field strings in memory after close
 */
"use strict";

const TAGS_FROM_REQUEST = [
  "serverinstancerequest",
  "blazesdkversion",
  "connectionprofile",
  "clientname",
  "fifa-2017-pc",
];

const CANDIDATE_REPLY_ROOTS = [
  "serverinstanceinfo",
  "serverinstancereply",
  "serverinstance",
];

const CANDIDATE_REPLY_FIELDS = [
  "address",
  "addr",
  "hostname",
  "host",
  "port",
  "secure",
  "name",
  "defaultdnsaddress",
  "messages",
  "trialservicename",
  "valu",
  "val",
  "ippairaddress",
  "hostnameaddress",
];

function mod() {
  return Process.getModuleByName("FIFA17.exe");
}

function readCString(p) {
  try {
    const s = p.readCString();
    if (s && s.length >= 2 && s.length < 500 && /^[\x09\x0a\x0d\x20-\x7e]+$/.test(s)) return s;
  } catch (_) {}
  return null;
}

function dumpHttpish(label) {
  const m = mod();
  const needles = ["POST /redirector", "HTTP/1.1 200", "serverinstancerequest", "serverinstanceinfo", "<?xml"];
  console.log("[observe] === HTTP-ish scan: " + label + " ===");
  for (let ni = 0; ni < needles.length; ni++) {
    const n = needles[ni];
    const bytes = [];
    for (let i = 0; i < n.length; i++) bytes.push(("0" + n.charCodeAt(i).toString(16)).slice(-2));
    const pat = bytes.join(" ");
    let hits = [];
    try {
      hits = Memory.scanSync(m.base, m.size, pat);
    } catch (e) {
      console.log("[observe] scan fail " + n + ": " + e);
      continue;
    }
    // Also scan RW heaps
    if (hits.length < 3) {
      const ranges = Process.enumerateRanges({ protection: "rw-", coalesce: true });
      for (let ri = 0; ri < ranges.length && hits.length < 8; ri++) {
        const r = ranges[ri];
        if (r.size > 16 * 1024 * 1024) continue;
        try {
          const h = Memory.scanSync(r.base, r.size, pat);
          for (let j = 0; j < h.length; j++) hits.push(h[j]);
        } catch (_) {}
      }
    }
    console.log("[observe] '" + n + "' hits=" + hits.length);
    for (let i = 0; i < Math.min(hits.length, 4); i++) {
      const a = hits[i].address;
      let ctx = "";
      try {
        ctx = a.sub(32).readUtf8String(240) || "";
      } catch (_) {
        try {
          ctx = a.readUtf8String(180) || "";
        } catch (__) {
          ctx = "(unreadable)";
        }
      }
      ctx = ctx.replace(/\r/g, "\\r").replace(/\n/g, "\\n");
      if (ctx.length > 220) ctx = ctx.slice(0, 220) + "…";
      console.log("[observe]   @" + a + " …" + ctx);
    }
  }
}

function hookDecoderErrors() {
  const m = mod();
  const markers = [
    "[XmlDecoder].readValue: Type contains unknown member.",
    "[XMLDecoder].Skip: Depth error in XML element(%s) and value(%s).",
    "[JsonDecoder].readValue: Type contains unknown member.",
  ];
  for (let mi = 0; mi < markers.length; mi++) {
    const marker = markers[mi];
    const bytes = [];
    for (let i = 0; i < Math.min(marker.length, 48); i++) {
      bytes.push(("0" + marker.charCodeAt(i).toString(16)).slice(-2));
    }
    const pat = bytes.join(" ");
    let hits;
    try {
      hits = Memory.scanSync(m.base, m.size, pat);
    } catch (e) {
      console.log("[observe] marker scan fail: " + e);
      continue;
    }
    console.log("[observe] marker '" + marker.slice(0, 40) + "…' hits=" + hits.length);
    // We cannot easily find all code xrefs without a disassembler;
    // instead hook OutputDebugStringA/W and printf-like if present.
  }

  const k32 = Process.getModuleByName("kernel32.dll");
  const odsa = k32.getExportByName("OutputDebugStringA");
  const odsw = k32.getExportByName("OutputDebugStringW");
  if (odsa) {
    Interceptor.attach(odsa, {
      onEnter(args) {
        const s = args[0].readCString();
        if (!s) return;
        if (/xml|heat|tdf|blaze|redirect|member|decode|serverinstance/i.test(s)) {
          console.log("[observe] OutputDebugStringA: " + s);
        }
      },
    });
    console.log("[observe] hooked OutputDebugStringA");
  }
  if (odsw) {
    Interceptor.attach(odsw, {
      onEnter(args) {
        let s;
        try {
          s = args[0].readUtf16String();
        } catch (_) {
          return;
        }
        if (!s) return;
        if (/xml|heat|tdf|blaze|redirect|member|decode|serverinstance/i.test(s)) {
          console.log("[observe] OutputDebugStringW: " + s);
        }
      },
    });
    console.log("[observe] hooked OutputDebugStringW");
  }
}

function hookConnect() {
  const ws2 = Process.getModuleByName("ws2_32.dll");
  const connect = ws2.getExportByName("connect");
  Interceptor.attach(connect, {
    onEnter(args) {
      const sa = args[1];
      const family = sa.readU16();
      if (family !== 2) return; // AF_INET
      const port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
      const ip =
        sa.add(4).readU8() +
        "." +
        sa.add(5).readU8() +
        "." +
        sa.add(6).readU8() +
        "." +
        sa.add(7).readU8();
      if (port === 42230 || port === 10041 || port === 8000 || port === 443 || port === 4433) {
        const star = port === 10041 ? "★★★ BLAZE " : port === 8000 ? "★ FUT " : "";
        console.log("[observe] " + star + "connect " + ip + ":" + port);
        if (port === 42230) {
          // After a short delay, dump HTTP-ish (request encoding happens around here)
          setTimeout(function () {
            dumpHttpish("during/after-42230");
          }, 2500);
        }
      }
    },
  });
  console.log("[observe] hooked connect");
}

function hookClosesocketSniff() {
  const ws2 = Process.getModuleByName("ws2_32.dll");
  const closesocket = ws2.getExportByName("closesocket");
  let armed = false;
  Interceptor.attach(closesocket, {
    onEnter() {
      if (armed) return;
      // Heuristic: after first redirector cycle, dump
      armed = true;
      setTimeout(function () {
        dumpHttpish("after-closesocket");
        console.log("[observe] === candidate reply field presence (rw memory) ===");
        const ranges = Process.enumerateRanges({ protection: "rw-", coalesce: true });
        for (let fi = 0; fi < CANDIDATE_REPLY_FIELDS.length; fi++) {
          const field = CANDIDATE_REPLY_FIELDS[fi];
          const tag = "<" + field + ">";
          const bytes = [];
          for (let i = 0; i < tag.length; i++) bytes.push(("0" + tag.charCodeAt(i).toString(16)).slice(-2));
          const pat = bytes.join(" ");
          let total = 0;
          for (let ri = 0; ri < ranges.length; ri++) {
            const r = ranges[ri];
            if (r.size > 8 * 1024 * 1024) continue;
            try {
              total += Memory.scanSync(r.base, r.size, pat).length;
            } catch (_) {}
          }
          if (total > 0) console.log("[observe] FOUND in RW: " + tag + " x" + total);
        }
        for (let ri = 0; ri < CANDIDATE_REPLY_ROOTS.length; ri++) {
          const root = CANDIDATE_REPLY_ROOTS[ri];
          const tag = "<" + root;
          const bytes = [];
          for (let i = 0; i < tag.length; i++) bytes.push(("0" + tag.charCodeAt(i).toString(16)).slice(-2));
          const pat = bytes.join(" ");
          let total = 0;
          for (let rxi = 0; rxi < ranges.length; rxi++) {
            const r = ranges[rxi];
            if (r.size > 8 * 1024 * 1024) continue;
            try {
              total += Memory.scanSync(r.base, r.size, pat).length;
            } catch (_) {}
          }
          console.log("[observe] root <" + root + "…> RW hits=" + total);
        }
        console.log("[observe] request tags (sanity):");
        for (let ti = 0; ti < TAGS_FROM_REQUEST.length; ti++) {
          console.log("[observe]   known-from-capture: " + TAGS_FROM_REQUEST[ti]);
        }
      }, 800);
    },
  });
  console.log("[observe] hooked closesocket → delayed dump");
}

console.log("[observe] start — receive what the game asks, do not invent");
hookConnect();
hookClosesocketSniff();
hookDecoderErrors();
// No startup full-memory scan (causes Frida timeout on FIFA17).
// Dumps run after :42230 connect / closesocket only.
console.log("[observe] ready — go Ultimate Team now");
