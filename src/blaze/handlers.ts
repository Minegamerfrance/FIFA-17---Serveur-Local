import type { BlazePacket } from "../shared/blazePacket.js";
import { Component, emptyReply, tdfReply, buildBlazePacket, MsgType } from "../shared/blazePacket.js";
import { TdfReader, TdfType, TdfWriter } from "../shared/tdf.js";
import type { BlazeSession } from "./sessions.js";
import { config } from "../config.js";
import { tryMatchmake, recordMatchResult, getQueueStatus } from "./matchmaking.js";
import { registerHandler } from "./router.js";
import { writePreAuthReply, preAuthHeaderStyle } from "./preauth.js";
import { log } from "../shared/logger.js";

export function registerAllHandlers() {
  // We will register a catch-all for now, or just export a function that registers everything.
  // Since we don't know the exact command IDs for everything, we'll register the known ones.
}

function authAccountReady(): boolean {
  const raw = (process.env.AUTH_ACCOUNT_READY ?? "").trim().toLowerCase();
  return raw === "1" || raw === "true" || raw === "yes" || raw === "ready";
}

function authSpamValue(defaultValue: number): number {
  const raw = (process.env.AUTH_SPAM_VALUE ?? "").trim();
  if (raw.length === 0) {
    return defaultValue;
  }
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : defaultValue;
}

/**
 * Legal-URL Auth profiles fill PRIV/TSUI/TURI/LDHT/THST with distinct paths.
 * - plst-legal-local: http://127.0.0.1:4433/legal/* (Nucleus HTTP)
 * - plst-legal-ea / plst-legal-https: https://accounts.ea.com/legal/* (Nucleus HTTPS :443)
 */
function authLegalProfileKind(): "local" | "ea" | null {
  const profile = (process.env.AUTH_REPLY_PROFILE ?? "").trim().toLowerCase();
  if (
    profile === "plst-legal-ea" ||
    profile === "plst-legal-https" ||
    profile.includes("legal-ea") ||
    profile.includes("legal-https")
  ) {
    return "ea";
  }
  if (profile === "plst-legal-local" || profile.includes("legal-local")) {
    return "local";
  }
  const raw = (process.env.AUTH_LEGAL_LOCAL ?? "").trim().toLowerCase();
  if (raw === "1" || raw === "true" || raw === "yes") return "local";
  return null;
}

function authLegalUrlsEnabled(): boolean {
  return authLegalProfileKind() !== null;
}

function authLegalBaseUrl(): string {
  const fromEnv = (process.env.AUTH_LEGAL_BASE_URL ?? "").trim();
  if (fromEnv) return fromEnv.replace(/\/$/, "");
  if (authLegalProfileKind() === "ea") return "https://accounts.ea.com";
  return `http://${config.host}:${config.nucleusPort}`;
}

function authLegalUrls(): {
  PRIV: string;
  TSUI: string;
  TURI: string;
  LDHT: string;
  THST: string;
} {
  const b = authLegalBaseUrl();
  return {
    PRIV: `${b}/legal/privacy`,
    TSUI: `${b}/legal/terms-ui`,
    TURI: `${b}/legal/terms`,
    LDHT: `${b}/legal/ldht`,
    THST: `${b}/legal/thst`,
  };
}

/**
 * FIFA 17 Authentication/10 (Origin auth-code: AUTH/EXTB/EXTI).
 *
 * Binary proof: RTTI has LoginResponse + LoginData::mPersonaDetailsList,
 * and FullLoginResponse count = 0. So the contract is flat LoginResponse
 * (PLST/SKEY/UID), not SESS/PDTL FullLoginResponse from later Blaze gens.
 *
 * AUTH_REPLY_PROFILE=full keeps the old SESS shape for A/B only.
 * AUTH_REPLY_PROFILE=plst-legal-local|plst-legal-ea fills legal URL fields for SDB panel test.
 */
export function writeLoginResponse(w: TdfWriter, session: BlazeSession): void {
  const now = Math.floor(Date.now() / 1000) >>> 0;
  const profile = (process.env.AUTH_REPLY_PROFILE ?? "plst").trim().toLowerCase();
  const referenceMinimal = profile === "plst-reference";
  const accountReady = authAccountReady();
  const spam = authSpamValue(accountReady ? 0 : 1);
  const legal = !referenceMinimal && authLegalUrlsEnabled() ? authLegalUrls() : null;
  // Pocket Relay's known-good FIFA-era Origin response sends SPAM=false.
  // FIFA 17 interprets SPAM=true as requiring the information-sharing signup
  // panel, not as an already accepted preference.
  if (!referenceMinimal) w.writeInteger("AGUP", accountReady ? 1 : 0);
  w.writeString("LDHT", legal?.LDHT ?? "");
  w.writeInteger("NTOS", 0);
  w.writeString("PCTK", `LOCAL-PCTK-${session.nucleusId}`);
  w.writeList("PLST", TdfType.Struct, [
    (persona) => {
      persona.writeString("DSNM", session.name);
      persona.writeInteger("LAST", now);
      persona.writeInteger("PID", session.personaId);
      persona.writeInteger("STAS", 0);
      persona.writeInteger("XREF", 0);
      persona.writeInteger("XTYP", 0);
      persona.endStruct();
    },
  ]);
  w.writeString("PRIV", legal?.PRIV ?? "");
  w.writeString("SKEY", `LOCAL-SKEY-${session.blazeId}`);
  w.writeInteger("SPAM", spam);
  w.writeString("THST", legal?.THST ?? "");
  w.writeString("TSUI", legal?.TSUI ?? "");
  w.writeString("TURI", legal?.TURI ?? "");
  w.writeInteger("UID", session.nucleusId);
}

/** Legacy FullLoginResponse (SESS/PDTL) — not present in FIFA17.exe RTTI. */
export function writeFullLoginResponse(w: TdfWriter, session: BlazeSession): void {
  const now = Math.floor(Date.now() / 1000) >>> 0;
  const accountReady = authAccountReady();
  const spam = authSpamValue(accountReady ? 0 : 1);
  const legal = authLegalUrlsEnabled() ? authLegalUrls() : null;
  w.writeInteger("AGUP", accountReady ? 1 : 0);
  w.writeString("LDHT", legal?.LDHT ?? "");
  w.writeInteger("NTOS", 0);
  w.writeString("PCTK", `LOCAL-PCTK-${session.nucleusId}`);
  w.writeString("PRIV", legal?.PRIV ?? "");
  w.writeStruct("SESS", (sessionInfo) => {
    sessionInfo.writeInteger("BUID", session.blazeId);
    sessionInfo.writeInteger("FRST", 0);
    sessionInfo.writeString("KEY", `LOCAL-SKEY-${session.blazeId}`);
    sessionInfo.writeInteger("LLOG", now);
    sessionInfo.writeString("MAIL", `${session.name}@fifa17.local`);
    sessionInfo.writeStruct("PDTL", (persona) => {
      persona.writeString("DSNM", session.name);
      persona.writeInteger("LAST", now);
      persona.writeInteger("PID", session.personaId);
      persona.writeInteger("STAS", 0);
      persona.writeInteger("XREF", 0);
      persona.writeInteger("XTYP", 0);
    });
    sessionInfo.writeInteger("UID", session.nucleusId);
  });
  w.writeInteger("SPAM", spam);
  w.writeString("THST", legal?.THST ?? "");
  w.writeString("TSUI", legal?.TSUI ?? "");
  w.writeString("TURI", legal?.TURI ?? "");
}

/**
 * SessionInfo-shaped reply (LoginPersona / SilentLogin SESS body).
 * FIFA17.exe has SessionInfo RTTI; useful A/B vs flat LoginResponse.
 */
export function writeSessionInfoReply(w: TdfWriter, session: BlazeSession): void {
  const now = Math.floor(Date.now() / 1000) >>> 0;
  w.writeInteger("BUID", session.blazeId);
  w.writeInteger("FRST", 0);
  w.writeString("KEY", `LOCAL-SKEY-${session.blazeId}`);
  w.writeInteger("LLOG", now);
  w.writeString("MAIL", `${session.name}@fifa17.local`);
  w.writeStruct("PDTL", (persona) => {
    persona.writeString("DSNM", session.name);
    persona.writeInteger("LAST", now);
    persona.writeInteger("PID", session.personaId);
    persona.writeInteger("STAS", 0);
    persona.writeInteger("XREF", 0);
    persona.writeInteger("XTYP", 0);
  });
  w.writeInteger("UID", session.nucleusId);
}

/** @deprecated alias — prefer writeLoginResponse */
export function writeOriginTokenLoginReply(w: TdfWriter, session: BlazeSession): void {
  const profile = (process.env.AUTH_REPLY_PROFILE ?? "plst").trim().toLowerCase();
  if (profile === "full") {
    writeFullLoginResponse(w, session);
  } else if (profile === "persona" || profile === "session") {
    writeSessionInfoReply(w, session);
  } else if (profile === "empty") {
    // intentional no TDF fields — layer test only
  } else {
    // plst, plst-legal-*, and default: flat LoginResponse (PLST), not SESS
    writeLoginResponse(w, session);
  }
}

/** UserSessions NotifyUserAdded (cmd 2) — BlazeServer sends this after silent/persona login. */
function buildNotifyUserAdded(session: BlazeSession, headerStyle: BlazePacket["headerStyle"]): Buffer {
  const w = new TdfWriter();
  w.writeStruct("DATA", (data) => {
    data.writeUnion("ADDR", 0x7f);
    data.writeString("BPS", "");
    data.writeString("CTY", "");
    data.writeMap("DMAP", TdfType.Integer, TdfType.Integer, [
      { key: 0x70001, value: 55 },
      { key: 0x70002, value: 707 },
    ]);
    data.writeInteger("HWFG", 0);
    data.writeStruct("QDAT", (q) => {
      q.writeInteger("DBPS", 0);
      q.writeInteger("NATT", 0);
      q.writeInteger("UBPS", 0);
    });
    data.writeInteger("UATT", 0);
  });
  w.writeStruct("USER", (user) => {
    // BlazeServer uses the connection/blaze user id here, not nucleus UID.
    user.writeInteger("AID", session.blazeId);
    user.writeInteger("ALOC", 0x656e5553); // enUS
    user.writeInteger("ID", session.personaId);
    user.writeString("NAME", session.name);
  });
  return buildBlazePacket({
    component: Component.UserSessions,
    command: 0x2,
    msgNum: 0,
    msgType: MsgType.Notification,
    payload: w.toBuffer(),
    headerStyle,
  });
}

/** UserSessions UserUpdated (cmd 5). */
function buildNotifyUserUpdated(session: BlazeSession, headerStyle: BlazePacket["headerStyle"]): Buffer {
  const w = new TdfWriter();
  w.writeInteger("FLGS", 3);
  w.writeInteger("ID", session.personaId);
  return buildBlazePacket({
    component: Component.UserSessions,
    command: 0x5,
    msgNum: 0,
    msgType: MsgType.Notification,
    payload: w.toBuffer(),
    headerStyle,
  });
}

/**
 * UserSessions UserAuthenticated (cmd 8).
 *
 * FIFA's local-user receiver consumes this login-info event to bind the
 * authenticated persona to the front-end's local-session slot. UserAdded
 * alone only creates the user record, leaving the local id at zero.
 * Shape recovered from the working FIFA 14 Local FUT Blaze sequence.
 */
function buildNotifyUserAuthenticated(
  session: BlazeSession,
  headerStyle: BlazePacket["headerStyle"],
): Buffer {
  const now = Math.floor(Date.now() / 1000) >>> 0;
  const w = new TdfWriter();
  w.writeInteger("ALOC", 0x656e5553); // enUS
  w.writeInteger("BUID", session.blazeId);
  w.writeString("DSNM", session.name);
  w.writeInteger("FRST", 0);
  w.writeString("KEY", `LOCAL-SKEY-${session.blazeId}`);
  w.writeInteger("LAST", 0);
  w.writeInteger("LLOG", now);
  w.writeString("MAIL", `${session.name}@fifa17.local`);
  w.writeInteger("PID", session.personaId);
  w.writeInteger("PLAT", 4); // legacy Blaze ExternalSystemId::PC
  w.writeInteger("UID", session.nucleusId);
  w.writeInteger("USTP", 1);
  w.writeInteger("XREF", 0);
  return buildBlazePacket({
    component: Component.UserSessions,
    command: 0x8,
    msgNum: 0,
    msgType: MsgType.Notification,
    payload: w.toBuffer(),
    headerStyle,
  });
}

/** UserSessions UserSessionExtendedDataUpdate (cmd 1). */
function buildNotifyExtendedDataUpdate(session: BlazeSession, headerStyle: BlazePacket["headerStyle"]): Buffer {
  const w = new TdfWriter();
  w.writeStruct("DATA", (data) => {
    data.writeString("BPS", "ea-sjc");
    data.writeString("CTY", "");
    data.writeInteger("HWFG", 0);
    data.writeInteger("UATT", 0);
  });
  w.writeInteger("SUBS", 1);
  w.writeInteger("USID", session.blazeId);
  return buildBlazePacket({
    component: Component.UserSessions,
    command: 0x1,
    msgNum: 0,
    msgType: MsgType.Notification,
    payload: w.toBuffer(),
    headerStyle,
  });
}

/**
 * CensusData NotifyServerCensusData (notification 1).
 *
 * FIFA 17 subscribes with Census/5 and RSUB=1.  The BlazeSDK wire contract
 * answers the RPC first, then publishes the current census snapshot through
 * notification 1.  A local server has no component census entries yet, so the
 * canonical snapshot is an empty TDFL list (not an empty packet).
 */
function buildNotifyServerCensusData(headerStyle: BlazePacket["headerStyle"]): Buffer {
  const w = new TdfWriter();
  w.writeList("TDFL", TdfType.Struct, []);
  return buildBlazePacket({
    component: Component.Census,
    command: 0x1,
    msgNum: 0,
    msgType: MsgType.Notification,
    payload: w.toBuffer(),
    headerStyle,
  });
}

const LOCALIZED_STRINGS: Record<string, string> = {
  SDB_ORIGIN_ACCT_OPTIN_HEADER: "Options de communication",
  SDB_ORIGIN_ACCT_OPTIN_BODY: "Choisissez les informations que vous souhaitez recevoir.",
  SDB_ORIGIN_ACCT_SIGNUP_FOR_EA_INFO: "Recevoir des informations EA",
  SDB_INFO_SHARING: "Partage d'informations",
  SDB_ORIGIN_ACCOUNT_CREATION_SUCCESS: "Compte Origin configure avec succes",
  SDB_ORIGIN_ACCT_INFO_TO_SHARE: "Informations a partager",
  SDB_ORIGIN_ACCT_SIGNUP_FOR_ORIGIN_INFO: "Recevoir des informations d'Origin",
  SDB_ORIGIN_ACCT_SIGNUP_FOR_PARTNER_INFO: "Recevoir des informations des partenaires EA",
};

function readLocalizationRequest(payload: Buffer): { ids: string[]; lang: number } {
  try {
    const fields = new TdfReader(payload).readStructFields();
    const langField = fields.find((field) => field.tag === "LANG");
    const lsid = fields.find((field) => field.tag === "LSID");
    const lang =
      langField?.value.type === TdfType.Integer
        ? Number(langField.value.value)
        : 0x66724652; // "frFR" in Blaze locale form
    const ids =
      lsid?.value.type === TdfType.List
        ? lsid.value.value
            .map((value) => (value.type === TdfType.String ? value.value : ""))
            .filter((value) => value.length > 0)
        : [];
    return { ids, lang };
  } catch (e) {
    log(
      "warn",
      "blaze",
      `util_4 localization request decode failed: ${e instanceof Error ? e.message : String(e)}`,
    );
    return { ids: [], lang: 0x66724652 };
  }
}

function readIntegerField(payload: Buffer, tag: string, fallback: number): number {
  try {
    const fields = new TdfReader(payload).readStructFields();
    const field = fields.find((item) => item.tag === tag);
    if (field?.value.type === TdfType.Integer) {
      return Number(field.value.value) >>> 0;
    }
  } catch (_) {}
  return fallback >>> 0;
}

function readStringField(payload: Buffer, tag: string, fallback: string): string {
  try {
    const fields = new TdfReader(payload).readStructFields();
    const field = fields.find((item) => item.tag === tag);
    if (field?.value.type === TdfType.String) {
      return field.value.value;
    }
  } catch (_) {}
  return fallback;
}

export function handleBlazeRequestLegacy(req: BlazePacket, session: BlazeSession): Buffer[] {
  const replies: Buffer[] = [];

  // Authentication / login
  if (req.component === Component.Authentication) {
    // Authentication/0x46 is logout. FIFA sends it with an empty payload
    // during the early online bootstrap. A login-shaped payload here is
    // semantically wrong and can leave the client state machine inconsistent.
    if (req.command === 0x46) {
      replies.push(emptyReply(req));
      return replies;
    }
    if (req.command === 0x0a) {
      const profile = process.env.AUTH_REPLY_PROFILE ?? "plst";
      const notify = process.env.AUTH_NOTIFY !== "0";
      const accountReady = authAccountReady();
      const spam = authSpamValue(accountReady ? 0 : 1);
      // Layer test: no Blaze reply at all — if logout still ~30s, timer is NOT waiting on TDF body.
      if (profile === "none" || profile === "silent") {
        log(
          "info",
          "blaze",
          "AUTH_REPLY_PROFILE none — NO reply to Auth/10 (layer test; expect timeout shift if Blaze reply mattered)",
        );
        return replies;
      }
      const legalKind = authLegalProfileKind();
      const legal = legalKind ? authLegalUrls() : null;
      const profileLog =
        legalKind
          ? `${profile} fields=AGUP,LDHT,NTOS,PCTK,PLST,PRIV,SKEY,SPAM,THST,TSUI,TURI,UID legalBase=${authLegalBaseUrl()}`
          : profile === "full"
            ? "full-login-sess fields=AGUP,LDHT,NTOS,PCTK,PRIV,SESS{...},SPAM,THST,TSUI,TURI"
            : profile === "persona" || profile === "session"
              ? "session-info fields=BUID,FRST,KEY,LLOG,MAIL,PDTL,UID"
              : profile === "empty"
                ? "empty-payload (no TDF fields)"
                : "login-response-plst fields=AGUP,LDHT,NTOS,PCTK,PLST[{DSNM,LAST,PID,STAS,XREF,XTYP}],PRIV,SKEY,SPAM,THST,TSUI,TURI,UID";
      log(
        "info",
        "blaze",
        `AUTH_REPLY_PROFILE=${profile} ${profileLog} accountReady=${accountReady ? "on" : "off"} AGUP=${accountReady ? 1 : 0} SPAM=${spam} notify=${notify ? "UserAuthenticated+UserAdded+ExtendedData" : "off"}`,
      );
      if (legal) {
        log(
          "info",
          "blaze",
          `AUTH_LEGAL_URLS PRIV=${legal.PRIV} TSUI=${legal.TSUI} TURI=${legal.TURI} LDHT=${legal.LDHT} THST=${legal.THST}`,
        );
      }
      replies.push(
        tdfReply(req, (w) => {
          writeOriginTokenLoginReply(w, session);
        }),
      );
      // Same post-login notifies as BlazeServer SilentLogin / LoginPersona.
      // A/B: AUTH_NOTIFY=0 skips them (PLST-only).
      if (notify) {
        replies.push(buildNotifyUserAuthenticated(session, req.headerStyle));
        replies.push(buildNotifyUserAdded(session, req.headerStyle));
        replies.push(buildNotifyExtendedDataUpdate(session, req.headerStyle));
      }
      return replies;
    }
    if (req.command === 0x20 || req.command === 0x1d) {
      let requestedGroups = ["FIFA17PCBoxContent"];
      try {
        const fields = new TdfReader(req.payload).readStructFields();
        const groups = fields.find((field) => field.tag === "GNLS");
        if (groups?.value.type === TdfType.List) {
          const decoded = groups.value.value
            .map((value) => (value.type === TdfType.String ? value.value : ""))
            .filter((value) => value.length > 0);
          if (decoded.length > 0) requestedGroups = decoded;
        }
      } catch (_) {}
      replies.push(
        tdfReply(req, (w) => {
          w.writeList(
            "NLST",
            TdfType.Struct,
            requestedGroups.map((groupName, index) => (entitlement) => {
              entitlement.writeString("DEVI", "");
              entitlement.writeString("GDAY", "2016-09-27T00:00:00Z");
              entitlement.writeString("GNAM", groupName);
              entitlement.writeInteger("ID", index + 1);
              entitlement.writeInteger("ISCO", 0);
              entitlement.writeInteger("PID", session.personaId);
              entitlement.writeString("PJID", "FIFA17");
              entitlement.writeInteger("PRCA", 2);
              entitlement.writeString("PRID", "fifa17_pc");
              entitlement.writeInteger("STAT", 2);
              entitlement.writeInteger("STRC", 1);
              entitlement.writeString("TAG", "FIFA17PCFUTContentUnlocks");
              entitlement.writeString("TDAY", "");
              entitlement.writeInteger("TYPE", 1);
              entitlement.writeInteger("UCNT", 0);
              entitlement.writeInteger("VER", 1);
              // A struct inside a TDF list is delimiter-terminated. Without
              // this marker the next entitlement is consumed as part of the
              // first one, leaving FIFA with one mixed grant and one empty
              // grant. This matches FUT 14's tdf_list_groups encoding.
              entitlement.endStruct();
            }),
          );
        }),
      );
      log(
        "info",
        "blaze",
        `AUTH_ENTITLEMENTS groups=${requestedGroups.join(",")} entries=${requestedGroups.length}`,
      );
      return replies;
    }
    replies.push(
      tdfReply(req, (w) => {
        w.writeInteger("BUID", session.blazeId);
        w.writeString("MAIL", `${session.name}@fifa17.local`);
        w.writeString("ANON", "0");
        w.writeInteger("UID", session.nucleusId);
        w.writeString("DSNM", session.name);
        w.writeInteger("PID", session.personaId);
        w.writeInteger("SESS", session.blazeId);
      }),
    );
    return replies;
  }

  // Util: ping / preAuth / postAuth / client config
  if (req.component === Component.Util) {
    if (req.command === 2 /* ping */) {
      // Proven: ANY ping reply (empty / unix STIM / uptime STIM) crashes ~200ms later.
      // PING_SWALLOW (default) keeps client alive 27s+. Keepalive via long pingPeriod.
      // PING_SWALLOW=0 forces STIM uptime (debug only — expected crash).
      if (process.env.PING_SWALLOW !== "0") {
        log("info", "blaze-trace", `PING_SWALLOW msgNum=${req.msgNum} (no reply)`);
        return replies;
      }
      // PingResponse.STIM is a native uint32 server timestamp.
      const stim = Math.floor(Date.now() / 1000) >>> 0;
      replies.push(
        tdfReply(req, (w) => {
          w.writeInteger("STIM", stim);
        }),
      );
      return replies;
    }
    if (req.command === 4 /* localizeStrings */) {
      const localizationRequest = readLocalizationRequest(req.payload);
      const ids =
        localizationRequest.ids.length > 0 ? localizationRequest.ids : Object.keys(LOCALIZED_STRINGS);
      const seen = new Set<string>();
      const entries = ids
        .filter((id) => {
          if (seen.has(id)) return false;
          seen.add(id);
          return true;
        })
        .map((id) => ({
          key: id,
          value: LOCALIZED_STRINGS[id] ?? id,
        }));
      const localizeMode = (process.env.BLAZE_LOCALIZE_MODE ?? "smap").trim().toLowerCase();
      log(
        "info",
        "blaze",
        `BLAZE_LOCALIZE_MODE ${localizeMode} lang=${localizationRequest.lang} ids=${entries.length} first=${entries[0]?.key ?? "none"}`,
      );
      replies.push(
        tdfReply(req, (w) => {
          if (localizeMode === "smap") {
            // FIFA 17 LocalizeStringsResponse.localizedStrings:
            //   SMAP: map<string, string>
            // Extracted from the game's TDF member table:
            //   localizedStrings tag=SMAP, key=string, value=string.
            w.writeMap("SMAP", TdfType.String, TdfType.String, entries);
          } else if (localizeMode === "map") {
            w.writeMap("STRS", TdfType.String, TdfType.String, entries);
          } else if (localizeMode === "list") {
            // FIFA sends Util/localizeStrings as LSID: list<string>. The matching
            // legacy reply shape is STRS: list<string>, preserving request order.
            w.writeStringList(
              "STRS",
              entries.map((entry) => entry.value),
            );
          } else if (localizeMode === "usertext") {
            w.writeList(
              "STRS",
              TdfType.Struct,
              entries.map((entry) => (userText) => {
                userText.writeString("LSID", entry.key);
                userText.writeString("TEXT", entry.value);
                userText.endStruct();
              }),
            );
          } else {
            // Legacy A/B only. The game accepted this on the wire but ignored it in UI.
            w.writeMap("STRS", TdfType.Integer, TdfType.Struct, [
              {
                key: localizationRequest.lang,
                writeValue: (userStringList) => {
                  userStringList.writeList(
                    "STRS",
                    TdfType.Struct,
                    entries.map((entry) => (userText) => {
                      userText.writeString("LSID", entry.key);
                      userText.writeString("TEXT", entry.value);
                      userText.endStruct();
                    }),
                  );
                },
              },
            ]);
          }
        }),
      );
      return replies;
    }
    if (req.command === 1 /* fetchClientConfig */) {
      const configId = readStringField(req.payload, "CFID", "");
      const configs: Record<string, Array<{ key: string; value: string }>> = {
        OSDK_CORE: [
          { key: "JOIN_GAME_TIMEOUT", value: "60000" },
          { key: "OSDK_DISTBUFFERSIZE_IN", value: "32768" },
          { key: "OSDK_DISTBUFFERSIZE_OUT", value: "32768" },
          { key: "OSDK_KEEPALIVEINTERVAL", value: "30000" },
          { key: "OSDK_MATCHUP_TIMEOUT", value: "60000" },
          { key: "OSDK_MAXGAMES", value: "100" },
          { key: "OSDK_MAXROOMS", value: "100" },
          { key: "OSDK_PEERBUFFERSIZE", value: "32768" },
          { key: "OSDK_REGISTER_PRODUCT", value: "0" },
          { key: "OSDK_TICKER_COUNT", value: "0" },
        ],
        OSDK_CLIENT: [
          { key: "FUTBOOTCFGFILE_URL", value: "http://127.0.0.1:8000/futBoot.xml" },
          { key: "FUT_RS4_BASE_URL", value: "http://127.0.0.1:8000/" },
          { key: "FUT_URI", value: "http://127.0.0.1:8000/" },
          { key: "CARDS/DIRECTED_BLAZEENV", value: "prod" },
          { key: "FCC/FUT_DEPLOY_LANGUAGE", value: "fr_FR" },
          { key: "FUT_ENABLE_MENU", value: "1" },
          { key: "FUT_RS4_APIURL_PC", value: "http://127.0.0.1:8000/" },
          { key: "FUT_RS4_URL_PC", value: "http://127.0.0.1:8000/" },
          { key: "FUTDYNAMICMESSAGES_URL_BASE", value: "http://127.0.0.1:8000" },
          { key: "FUTDYNAMICMESSAGES_URL_GET_MESSAGES", value: "/messages" },
          { key: "FUTDYNAMICMESSAGES_TUTORIAL_MSG_URL", value: "/tutorials" },
          { key: "FUTDYNAMICMESSAGES_REQUEST_TIMEOUT", value: "5000" },
          { key: "FUTDYNAMICMESSAGES_REFRESH_INTERVAL", value: "300000" },
          { key: "FUT/MODULE_BASEURL_PC", value: "http://127.0.0.1:8000/" },
          { key: "FUT/SINGLE_BASEURL_PC", value: "http://127.0.0.1:8000/" },
          { key: "ONLINE/NO_AUTO_SQUAD", value: "0" },
          // FIFA 17 otherwise enters the legacy Profile Anywhere download
          // flow after supported-club selection and waits forever for the
          // retired EA PRAN service.
          { key: "ONLINE/PRAN_ON", value: "0" },
          // Match the working FIFA 14 first-account bootstrap.  A fresh local
          // profile has no FUT club yet, so advertising a returning user while
          // disabling tutorials sends Cards into a saved-club path that can
          // only render the empty loading dialog.
          { key: "FUT/FORCE_TUTORIALS", value: "0" },
          { key: "FUT/DISABLE_TUTORIALS", value: "0" },
          { key: "FUT/ALWAYS_SHOW_SMART_TUTORIALS", value: "0" },
          { key: "FUT/IS_RETURNING_USER", value: "1" },
          { key: "FUT_SKIP_ICEBREAKER_FLOW", value: "1" },
          { key: "ONLINE/ONLINE_PASS_REQUIRED", value: "0" },
          { key: "OSDK_DDP_UPGRADE_TO_DDR_ENABLED", value: "0" },
          { key: "OSDK_REGISTER_PRODUCT", value: "0" },
          { key: "OSDK_TOLLBOOTH_DDP_COMMERCE_ENABLED", value: "0" },
          { key: "OSDK_TOLLBOOTH_DDR_ONLINE_PASS_ENABLED", value: "0" },
          { key: "OSDK_TOLLBOOTH_ONLINE_PASS_ENABLED", value: "0" },
          { key: "OSDK_TOLLBOOTH_SEASON_TICKET_ENABLED", value: "0" },
          { key: "OSDK_TOLLBOOTH_SHOW_SEASON_TICKET_AT_LOGIN", value: "0" },
        ],
        OSDK_NUCLEUS: [
          // Match the working FIFA 14 OSDK contract. FIFA 17 treats the
          // CONNECT/PROXY/RETRY triplet as a different Nucleus generation and
          // immediately raises NucleusLoginFailed(0x12) without doing HTTP.
          { key: "NUCLEUS_ADDED_URL", value: "" },
          { key: "NUCLEUS_CREATE_INFO_URL", value: "" },
          { key: "NUCLEUS_CREATE_URL", value: "" },
          { key: "NUCLEUS_DEACTIVATED_INFO_URL", value: "" },
          { key: "NUCLEUS_DUPACCT_INFO_URL", value: "" },
          { key: "NUCLEUS_INCOMPLETE_URL", value: "" },
          { key: "OSDK_EASW_ALLOWED_LOCALES", value: "en_US,en_GB" },
          { key: "OSDK_EASW_CONNECT_RETRY_PERIOD", value: "5" },
          { key: "OSDK_REGISTER_PRODUCT", value: "0" },
        ],
        OSDK_WEBOFFER: [],
        OSDK_ABUSE_REPORTING: [],
        OSDK_XMS_ABUSE_REPORTING: [
          { key: "OSDK_XMS_ABUSE_REPORTING_URL", value: "" },
          { key: "OSDK_XMS_ABUSE_TYPES", value: "0" },
        ],
        OSDK_TICKER: [],
        OSDK_ARENA: [],
        OSDK_ROSTER: [],
      };
      const values = configs[configId] ?? [];
      log("info", "blaze", `UTIL_1 fetchClientConfig CFID=${configId || "<empty>"} entries=${values.length}`);
      replies.push(
        tdfReply(req, (w) => {
          w.writeMap("CONF", TdfType.String, TdfType.String, values);
        }),
      );
      return replies;
    }
    if (req.command === 0x16 /* updateNetworkInfo / client network state */) {
      const ubfl = readIntegerField(req.payload, "UBFL", 2);
      const udev = readStringField(req.payload, "UDEV", "");
      const uflg = readIntegerField(req.payload, "UFLG", 7);
      const ulrc = readIntegerField(req.payload, "ULRC", 0);
      const unat = readIntegerField(req.payload, "UNAT", 5);
      const usta = readIntegerField(req.payload, "USTA", 1);
      log(
        "info",
        "blaze",
        `UTIL_22 updateNetworkInfo echo UBFL=${ubfl} UDEV=${JSON.stringify(udev)} UFLG=${uflg} ULRC=${ulrc} UNAT=${unat} USTA=${usta}`,
      );
      replies.push(
        tdfReply(req, (w) => {
          w.writeInteger("UBFL", ubfl);
          w.writeString("UDEV", udev);
          w.writeInteger("UFLG", uflg);
          w.writeInteger("ULRC", ulrc);
          w.writeInteger("UNAT", unat);
          w.writeInteger("USTA", usta);
        }),
      );
      if (process.env.AUTH_NOTIFY !== "0") {
        replies.push(buildNotifyExtendedDataUpdate(session, req.headerStyle));
      }
      return replies;
    }
    if (req.command === 0x1c /* setClientState / opt-in state */) {
      const mode = readIntegerField(req.payload, "MODE", 1);
      const stat = readIntegerField(req.payload, "STAT", 0);
      log("info", "blaze", `UTIL_28 setClientState echo MODE=${mode} STAT=${stat}`);
      replies.push(
        tdfReply(req, (w) => {
          w.writeInteger("MODE", mode);
          w.writeInteger("STAT", stat);
        }),
      );
      return replies;
    }
    if (req.command === 7 /* preAuth */) {
      replies.push(
        tdfReply(
          req,
          (w) => {
            writePreAuthReply(req, w);
          },
          req.component,
          req.command,
          preAuthHeaderStyle(req),
        ),
      );
      return replies;
    }
    if (req.command === 8 /* postAuth */) {
      replies.push(
        tdfReply(req, (w) => {
          // Complete Blaze 3 post-auth bootstrap shape. FIFA uses these
          // generated structures to finish its service initialization and to
          // associate the authenticated UID with the local user slot.
          w.writeStruct("PSS", (p) => {
            p.writeString("ADRS", config.host);
            p.writeBlob("CSIG");
            p.writeString("PJID", "303107");
            p.writeInteger("PORT", 443);
            p.writeInteger("RPRT", 0x0f);
            p.writeInteger("TIID", 0);
          });
          w.writeStruct("TELE", (t) => {
            t.writeString("ADRS", config.host);
            t.writeInteger("ANON", 0);
            t.writeString("DISA", "");
            t.writeString("FILT", "-UION/****");
            t.writeInteger("LOC", 0x656e5553);
            t.writeString("NOOK", "");
            t.writeInteger("PORT", 42129);
            t.writeInteger("SDLY", 15000);
            t.writeString("SESS", "LOCAL-FIFA17-TELEMETRY");
            t.writeString("SKEY", "");
            t.writeInteger("SPCT", 0);
            t.writeString("STIM", "");
          });
          w.writeStruct("TICK", (t) => {
            t.writeString("ADRS", config.host);
            t.writeInteger("PORT", 8999);
            t.writeString("SKEY", `${session.blazeId},${config.host}:8999,fifa-2017-pc,0`);
          });
          w.writeStruct("UROP", (u) => {
            u.writeInteger("TMOP", 1);
            u.writeInteger("UID", session.nucleusId);
          });
        }),
      );
      return replies;
    }
    if (req.command === 10 /* userSettingsLoad */) {
      const key = readStringField(req.payload, "KEY", "");
      const value = session.userSettings[key] ?? "";
      log("info", "blaze", `UTIL_10 userSettingsLoad KEY=${JSON.stringify(key)} found=${key in session.userSettings ? 1 : 0}`);
      replies.push(
        tdfReply(req, (w) => {
          w.writeString("DATA", value);
        }),
      );
      return replies;
    }
    if (req.command === 11 /* userSettingsSave */) {
      const key = readStringField(req.payload, "KEY", "");
      const value = readStringField(req.payload, "DATA", "");
      if (key) session.userSettings[key] = value;
      log("info", "blaze", `UTIL_11 userSettingsSave KEY=${JSON.stringify(key)} bytes=${Buffer.byteLength(value)}`);
      replies.push(emptyReply(req));
      return replies;
    }
    // other util — empty ack
    replies.push(emptyReply(req));
    return replies;
  }

  // UserSessions
  if (req.component === Component.UserSessions) {
    // FIFA sends UserSessions/8 with USID=0 during the post-auth bootstrap.
    // This is an update/ack RPC, not a request for a synthetic user record.
    // The working FIFA 14 Blaze implementation also acknowledges commands 8
    // and 20 with an empty success.  Returning BUID/NAME/UID here feeds the
    // response into the wrong generated TDF class and can leave the local
    // user lookup pinned to id 0.
    if (req.command === 8 || req.command === 20) {
      replies.push(emptyReply(req));
      return replies;
    }
    replies.push(
      tdfReply(req, (w) => {
        w.writeInteger("BUID", session.blazeId);
        w.writeString("NAME", session.name);
        w.writeInteger("UID", session.nucleusId);
        w.writeUnion("ADDR", 0x0, (a) => {
          a.writeStruct("VALU", (v) => {
            v.writeString("HOST", session.externalIp || config.blazePublicHost);
            v.writeInteger("IP", 0);
            v.writeInteger("PORT", 0);
          });
        });
      }),
    );
    return replies;
  }

  // GameManager — matchmaking & game create
  if (req.component === Component.GameManager) {
    return handleGameManager(req, session);
  }

  // Typed post-login bootstrap responses recovered from the working FIFA 14
  // Local FUT Blaze sequence. FIFA decodes these generated response classes;
  // an empty success does not satisfy every bootstrap job.
  if (req.component === 2148 && req.command === 101) {
    replies.push(
      tdfReply(req, (w) => {
        // New-player CardHouse login: zero counters and no NAME/ABBR/CVER.
        // The missing club identity sends the retail client into onboarding.
        for (const tag of ["BNUS", "DRRC", "DRRL", "DRRO", "DRRW", "RWRD", "TNOW", "TRBS", "UID"]) {
          w.writeInteger(tag, 0);
        }
      }),
    );
    return replies;
  }
  if (req.component === 2148 && req.command === 104) {
    replies.push(
      buildBlazePacket({
        component: req.component,
        command: req.command,
        error: 1,
        msgNum: req.msgNum,
        msgType: MsgType.ErrorReply,
        payload: Buffer.alloc(0),
        headerStyle: req.headerStyle,
      }),
    );
    return replies;
  }
  if (req.component === 2148 && [102, 103, 106, 301, 709].includes(req.command)) {
    replies.push(emptyReply(req));
    return replies;
  }
  if (req.component === 2249 && req.command === 1) {
    replies.push(
      tdfReply(req, (w) => {
        w.writeList("LSST", TdfType.Struct, [
          (setting) => {
            setting.writeString("ID", "O_TKfilter");
            setting.writeInteger("LOCF", 0);
            setting.writeInteger("TOGG", 0);
            setting.endStruct();
          },
        ]);
      }),
    );
    return replies;
  }
  if (req.component === 2249 && req.command === 2) {
    replies.push(
      tdfReply(req, (w) => {
        w.writeList("LGRP", TdfType.Struct, [
          (group) => {
            group.writeString("ID", "O_SG_TCKR");
            group.writeStringList("LSET", ["O_TKfilter"]);
            group.endStruct();
          },
        ]);
      }),
    );
    return replies;
  }
  if (req.component === Component.Messaging && req.command === 2) {
    replies.push(tdfReply(req, (w) => w.writeInteger("MCNT", 0)));
    return replies;
  }
  if (req.component === Component.AssociationLists && req.command === 6) {
    replies.push(tdfReply(req, (w) => w.writeList("LMAP", TdfType.Struct, [])));
    return replies;
  }
  if (req.component === Component.Clubs && req.command === 1600) {
    replies.push(tdfReply(req, (w) => w.writeList("CIST", TdfType.Struct, [])));
    return replies;
  }
  if (req.component === Component.Clubs && req.command === 2600) {
    replies.push(
      tdfReply(req, (w) => {
        for (const tag of ["CLDS", "MXEV", "MXRV", "PUHR", "SOVR", "STRT"]) {
          w.writeInteger(tag, 0);
        }
      }),
    );
    return replies;
  }
  if (req.component === Component.Stats && req.command === 15) {
    replies.push(
      tdfReply(req, (w) => w.writeMap("KSIT", TdfType.String, TdfType.Struct, [])),
    );
    return replies;
  }
  if (req.component === Component.Stats && req.command === 3) {
    replies.push(tdfReply(req, (w) => w.writeList("GRPS", TdfType.Struct, [])));
    return replies;
  }
  if (req.component === Component.Stats && req.command === 20) {
    replies.push(
      tdfReply(req, (w) => {
        for (const tag of [
          "DBUF", "DHOU", "DLY", "DRET", "MBUF", "MDAY", "MHOU",
          "MLY", "MRET", "WBUF", "WDAY", "WHOU", "WLY", "WRET",
        ]) {
          w.writeInteger(tag, 0);
        }
      }),
    );
    return replies;
  }
  if (req.component === Component.Census && req.command === 5) {
    // FIFA 17: SubscribeToCensusDataUpdatesResponse.  The three tags and their
    // generated class layout were recovered directly from FIFA17.exe:
    // CNP=censusNotificationPeriod, NTMT=notificationTimeout,
    // RTMT=resubscribeTimeout.  Leaving them absent initializes every timer to
    // zero and makes the client resubmit Census/5 every frame.
    replies.push(
      tdfReply(req, (w) => {
        // Blaze TimeValue fields are serialized in microseconds.  Sending the
        // millisecond-looking values 60_000/120_000 made FIFA resubscribe in
        // roughly 250-400 ms (60 ms plus its scheduler cadence).
        w.writeInteger("CNP", 60_000_000);
        w.writeInteger("NTMT", 120_000_000);
        w.writeInteger("RTMT", 60_000_000);
      }),
    );
    // Do not publish TDFL=[] here. FIFA treats an empty update as an invalid
    // census snapshot and immediately retries with RSUB=1. A notification is
    // independent from the subscription reply and must wait until it contains
    // at least one real typed census item.
    return replies;
  }
  if (req.component === Component.Census && req.command === 1) {
    // Legacy subscribeToCensusData used by FIFA 14 / older Blaze generations.
    replies.push(emptyReply(req));
    replies.push(buildNotifyServerCensusData(req.headerStyle));
    return replies;
  }

  // Sponsored Events (0x081c), command 3: FIFA expects a typed URL rather
  // than an empty success. This is the same generated Blaze contract used by
  // the working FIFA 14 local server.
  if (req.component === 0x081c && req.command === 3) {
    replies.push(
      tdfReply(req, (w) =>
        w.writeString("URL", "http://127.0.0.1:8000/sponsored-events"),
      ),
    );
    return replies;
  }

  // Association lists / messaging / stats — acknowledge
  if (
    req.component === Component.AssociationLists ||
    req.component === Component.Messaging ||
    req.component === Component.Stats ||
    req.component === Component.Clubs ||
    req.component === Component.Inventory
  ) {
    replies.push(emptyReply(req));
    return replies;
  }

  replies.push(emptyReply(req));
  return replies;
}

function handleGameManager(req: BlazePacket, session: BlazeSession): Buffer[] {
  const replies: Buffer[] = [];
  const match = tryMatchmake(session);

  if (match) {
    // Reply to requester
    replies.push(
      tdfReply(req, (w) => {
        w.writeInteger("GID", match.gameId);
        w.writeInteger("GNAM", match.gameId);
        w.writeString("ATTR", "FUT_FRIENDLY");
        w.writeInteger("NRES", 0);
        w.writeList("PROS", 3 /* Struct */, [
          (p) => {
            p.writeInteger("UID", match.host.blazeId);
            p.writeString("NAME", match.host.name);
            p.writeInteger("SLOT", 0);
            p.endStruct();
          },
          (p) => {
            p.writeInteger("UID", match.guest.blazeId);
            p.writeString("NAME", match.guest.name);
            p.writeInteger("SLOT", 1);
            p.endStruct();
          },
        ]);
      }),
    );

    // Notify both sides that game started (best-effort packet)
    const notify = (target: BlazeSession, opponent: BlazeSession) =>
      buildBlazePacket({
        component: Component.GameManager,
        command: 0x0075, // NotifyGameSetup-ish
        msgNum: 0,
        msgType: MsgType.Notification,
        payload: (() => {
          const w = new TdfWriter();
          w.writeInteger("GID", match.gameId);
          w.writeInteger("BUID", target.blazeId);
          w.writeString("ONAM", opponent.name);
          w.writeInteger("OUID", opponent.blazeId);
          w.writeString("HOST", config.blazePublicHost);
          w.writeInteger("PORT", config.blazePort);
          return w.toBuffer();
        })(),
      });

    // Host/guest notifications are returned to the requesting socket only here;
    // the blaze server also broadcasts via matchmaking registry.
    void notify;
    replies.push(notify(session, session.blazeId === match.host.blazeId ? match.guest : match.host));
  } else {
    const status = getQueueStatus();
    replies.push(
      tdfReply(req, (w) => {
        w.writeInteger("QLEN", status.length);
        w.writeString("STAT", "QUEUED");
        w.writeInteger("BUID", session.blazeId);
      }),
    );
  }

  return replies;
}

export function buildMatchResultNotification(
  gameId: number,
  winnerBlazeId: number,
  scoreHome: number,
  scoreAway: number,
): Buffer {
  recordMatchResult(gameId, winnerBlazeId, scoreHome, scoreAway);
  const w = new TdfWriter();
  w.writeInteger("GID", gameId);
  w.writeInteger("WIN", winnerBlazeId);
  w.writeInteger("HSCR", scoreHome);
  w.writeInteger("ASCR", scoreAway);
  return buildBlazePacket({
    component: Component.GameManager,
    command: 0x0050,
    msgNum: 0,
    msgType: MsgType.Notification,
    payload: w.toBuffer(),
  });
}
