import type { BlazePacket } from "../shared/blazePacket.js";
import { Component, emptyReply, tdfReply, buildBlazePacket, MsgType } from "../shared/blazePacket.js";
import { TdfType, TdfWriter } from "../shared/tdf.js";
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

/**
 * FIFA 17 Authentication/10 (Origin auth-code: AUTH/EXTB/EXTI).
 *
 * Binary proof: RTTI has LoginResponse + LoginData::mPersonaDetailsList,
 * and FullLoginResponse count = 0. So the contract is flat LoginResponse
 * (PLST/SKEY/UID), not SESS/PDTL FullLoginResponse from later Blaze gens.
 *
 * AUTH_REPLY_PROFILE=full keeps the old SESS shape for A/B only.
 */
export function writeLoginResponse(w: TdfWriter, session: BlazeSession): void {
  const now = Math.floor(Date.now() / 1000) >>> 0;
  w.writeInteger("AGUP", 0);
  w.writeString("LDHT", "");
  w.writeInteger("NTOS", 0);
  w.writeString("PCTK", `LOCAL-PCTK-${session.nucleusId}`);
  w.writeList("PLST", TdfType.Struct, [
    (persona) => {
      persona.writeString("DSNM", session.name);
      persona.writeInteger("LAST", now);
      persona.writeInteger("PID", session.personaId);
      persona.writeInteger("STAS", 2); // ACTIVE
      persona.writeInteger("XREF", 0);
      persona.writeInteger("XTYP", 0);
      persona.endStruct();
    },
  ]);
  w.writeString("PRIV", "");
  w.writeString("SKEY", `LOCAL-SKEY-${session.blazeId}`);
  w.writeInteger("SPAM", 1);
  w.writeString("THST", "");
  w.writeString("TSUI", "");
  w.writeString("TURI", "");
  w.writeInteger("UID", session.nucleusId);
}

/** Legacy FullLoginResponse (SESS/PDTL) — not present in FIFA17.exe RTTI. */
export function writeFullLoginResponse(w: TdfWriter, session: BlazeSession): void {
  const now = Math.floor(Date.now() / 1000) >>> 0;
  w.writeInteger("AGUP", 0);
  w.writeString("LDHT", "");
  w.writeInteger("NTOS", 0);
  w.writeString("PCTK", `LOCAL-PCTK-${session.nucleusId}`);
  w.writeString("PRIV", "");
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
      persona.writeInteger("STAS", 2);
      persona.writeInteger("XREF", 0);
      persona.writeInteger("XTYP", 0);
    });
    sessionInfo.writeInteger("UID", session.nucleusId);
  });
  w.writeInteger("SPAM", 1);
  w.writeString("THST", "");
  w.writeString("TSUI", "");
  w.writeString("TURI", "");
}

/** @deprecated alias — prefer writeLoginResponse */
export function writeOriginTokenLoginReply(w: TdfWriter, session: BlazeSession): void {
  if (process.env.AUTH_REPLY_PROFILE === "full") {
    writeFullLoginResponse(w, session);
  } else {
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
    data.writeInteger("HWFG", 0);
    data.writeStruct("QDAT", (q) => {
      q.writeInteger("DBPS", 0);
      q.writeInteger("NATT", 0);
      q.writeInteger("UBPS", 0);
    });
    data.writeInteger("UATT", 0);
  });
  w.writeStruct("USER", (user) => {
    user.writeInteger("AID", session.nucleusId);
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
      const profile =
        process.env.AUTH_REPLY_PROFILE === "full" ? "full-login-sess" : "login-response-plst";
      log(
        "info",
        "blaze",
        profile === "full-login-sess"
          ? "AUTH_REPLY_PROFILE full-login-sess fields=AGUP,LDHT,NTOS,PCTK,PRIV,SESS{…},SPAM,THST,TSUI,TURI"
          : "AUTH_REPLY_PROFILE login-response-plst fields=AGUP,LDHT,NTOS,PCTK,PLST[{DSNM,LAST,PID,STAS,XREF,XTYP}],PRIV,SKEY,SPAM,THST,TSUI,TURI,UID + NotifyUserAdded/UserUpdated",
      );
      replies.push(
        tdfReply(req, (w) => {
          writeOriginTokenLoginReply(w, session);
        }),
      );
      // Same post-login notifies as BlazeServer SilentLogin / LoginPersona.
      replies.push(buildNotifyUserAdded(session, req.headerStyle));
      replies.push(buildNotifyUserUpdated(session, req.headerStyle));
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
    if (req.command === 1 /* fetchClientConfig */) {
      replies.push(
        tdfReply(req, (w) => {
          w.writeMap("CONF", TdfType.String, TdfType.String, [
            { key: "pingPeriod", value: "20s" },
            { key: "connIdleTimeout", value: "90s" },
            { key: "defaultRequestTimeout", value: "80s" },
          ]);
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
          w.writeStruct("TELE", (t) => {
            t.writeString("ADRS", `${config.host}:${config.futPort}`);
            t.writeInteger("PORT", config.futPort);
          });
          w.writeStruct("UROP", (u) => {
            u.writeInteger("TMOP", 1);
          });
        }),
      );
      return replies;
    }
    // other util — empty ack
    replies.push(emptyReply(req));
    return replies;
  }

  // UserSessions
  if (req.component === Component.UserSessions) {
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
