import type { BlazePacket, BlazeHeaderStyle } from "../shared/blazePacket.js";
import { TdfType, TdfWriter, TdfReader, fieldToObject } from "../shared/tdf.js";
import { config } from "../config.js";
import { log } from "../shared/logger.js";

/**
 * PreAuth reply header: always Fire2 native layout (encLen@4=0, comp@6, type@0xd).
 * Classic replies made the client treat component as encLen → stuck need=9.
 */
export function preAuthHeaderStyle(_req: BlazePacket): BlazeHeaderStyle {
  return "fire2";
}

const REDIRECTOR_SERVICE = () =>
  process.env.REDIRECTOR_SERVICE_NAME?.trim() || "fifa-2017-pc";

function authenticationSource(): string {
  return process.env.BLAZE_PREAUTH_ASRC?.trim() || "";
}

function registrationSource(): string {
  return process.env.BLAZE_PREAUTH_RSRC?.trim() || "";
}

function advertisedComponentIds(): number[] {
  const raw = process.env.BLAZE_PREAUTH_CIDS?.trim();
  if (!raw) return [];
  return raw
    .split(",")
    .map((value) => Number.parseInt(value.trim(), 10))
    .filter((value) => Number.isInteger(value) && value >= 0 && value <= 0xffff);
}

type Observed = {
  bsdk: string;
  clnt: string;
  csku: string;
  cver: string;
  env: string;
  loc: string;
  svcn: string;
};

function observeRequest(req: BlazePacket): Observed {
  const fallback: Observed = {
    bsdk: "15.1.1.3.0",
    clnt: "FIFA17",
    csku: "FIFAPC",
    cver: "3175939",
    env: "prod",
    loc: "3437530258",
    svcn: REDIRECTOR_SERVICE(),
  };
  try {
    const root = fieldToObject(new TdfReader(req.payload).readStructFields()) as Record<
      string,
      Record<string, string> | string
    >;
    const cinf = (root.CINF ?? {}) as Record<string, string>;
    const cdat = (root.CDAT ?? {}) as Record<string, string>;
    return {
      bsdk: cinf.BSDK || fallback.bsdk,
      clnt: cinf.CLNT || fallback.clnt,
      csku: cinf.CSKU || fallback.csku,
      cver: cinf.CVER || fallback.cver,
      env: cinf.ENV || fallback.env,
      loc: cinf.LOC || fallback.loc,
      svcn: REDIRECTOR_SERVICE() || cdat.SVCN || fallback.svcn,
    };
  } catch {
    return fallback;
  }
}

function writeTimeoutConf(w: TdfWriter): void {
  // Long pingPeriod: we swallow Util/2 replies (any STIM crashes FIFA).
  // Avoid ~20–27s Blaze idle drop while chasing Auth/Login.
  w.writeStruct("CONF", (c) => {
    c.writeMap("CONF", TdfType.String, TdfType.String, [
      { key: "connIdleTimeout", value: "600s" },
      { key: "defaultRequestTimeout", value: "80s" },
      { key: "pingPeriod", value: "300s" },
      { key: "voipHeadsetUpdateRate", value: "1000" },
      { key: "xlspConnectionIdleTimeout", value: "300" },
    ]);
  });
}

function writeMinimalQos(w: TdfWriter, qosHost: string): void {
  // BWPS with a real port (PSP=0 previously). No LTPS entries → no extra connects.
  const psp = Number(process.env.BLAZE_QOS_PORT?.trim()) || 17502;
  w.writeStruct("QOSS", (q) => {
    q.writeStruct("BWPS", (b) => {
      b.writeString("PSA", qosHost);
      b.writeInteger("PSP", psp);
      b.writeString("SNA", "ams");
    });
    q.writeInteger("LNP", 10);
    q.writeMap("LTPS", TdfType.String, TdfType.Struct, []);
    q.writeInteger("SVID", 0);
  });
}

/**
 * Neutral preAuth payload (BlazeServer field order).
 * Crash persists with ASRC=300294 + CIDS=[1,9] + STIM + FIX_TIMER — strip ME3 IDs.
 */
export function writePreAuthReply(req: BlazePacket, w: TdfWriter): void {
  const obs = observeRequest(req);
  const qosHost = config.blazePublicHost || config.host;
  const style = preAuthHeaderStyle(req);
  const authSource = authenticationSource();
  const registrationSourceValue = registrationSource();
  const componentIds = advertisedComponentIds();

  log(
    "info",
    "blaze-trace",
    `PREAUTH style=${style} INST=${obs.svcn} SVER_BSDK=${obs.bsdk} CLNT=${obs.clnt} CSKU=${obs.csku} CVER=${obs.cver} ASRC=${JSON.stringify(authSource)} CIDS=${JSON.stringify(componentIds)} RSRC=${JSON.stringify(registrationSourceValue)}`,
  );

  w.writeInteger("ANON", 0);
  // Empty by default (stable); test FIFA17DEFAULTID independently from CIDS.
  w.writeString("ASRC", authSource);
  // Default stays empty (known stable). A/B Auth gate test:
  // BLAZE_PREAUTH_CIDS=1,9 advertises Authentication + Util only.
  w.writeList(
    "CIDS",
    TdfType.Integer,
    componentIds.map((componentId) => (item) => {
      item.writeCompact(componentId);
    }),
  );
  w.writeString("CNGN", "");
  writeTimeoutConf(w);
  w.writeString("INST", obs.svcn);
  w.writeInteger("MINR", 0);
  w.writeString("NASP", "cem_ea_id");
  w.writeString("PILD", "");
  w.writeString("PLAT", "pc");
  w.writeString("PTAG", "");
  writeMinimalQos(w, qosHost);
  w.writeString("RSRC", registrationSourceValue);
  w.writeString("SVER", `Blaze ${obs.bsdk}`);
}
