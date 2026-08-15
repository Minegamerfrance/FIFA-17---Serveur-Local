import { parseBlazePacket, buildBlazePacket, MsgType, Component } from "../shared/blazePacket.js";
import { log } from "../shared/logger.js";
import type { BlazeSession } from "./sessions.js";
import { handleBlazeRequestLegacy } from "./handlers.js";
import { utilCommandName } from "./trace.js";

type BlazeRequest = NonNullable<ReturnType<typeof parseBlazePacket>>;
type ReplyCallback = (reply: Buffer, handler?: string) => void;
type Handler = (req: BlazeRequest, session: BlazeSession, write: ReplyCallback) => void;

const handlers = new Map<number, Map<number, Handler>>();

export function registerHandler(component: number, command: number, handler: Handler) {
  if (!handlers.has(component)) {
    handlers.set(component, new Map());
  }
  handlers.get(component)!.set(command, handler);
}

/**
 * Observe-only: frames that are not Blaze request Messages.
 * First post-TLS frame was msgType=4 / comp=0 / cmd=0 / empty — looks like control.
 * Auto empty-Reply on those may reset the session; do not invent a response yet.
 */
export function isBlazeNonRequestFrame(req: BlazeRequest): boolean {
  if (req.msgType !== MsgType.Message) return true;
  if (
    req.component === 0 &&
    req.command === 0 &&
    req.payload.length === 0 &&
    req.error === 0
  ) {
    return true;
  }
  return false;
}

export function routeBlazeRequest(req: BlazeRequest, session: BlazeSession, write: ReplyCallback): void {
  if (isBlazeNonRequestFrame(req)) {
    log(
      "info",
      "blaze",
      `CTRL/non-request OBSERVE (no reply) component=${req.component} command=${req.command} msgType=${req.msgType} options=${req.options} msgNum=${req.msgNum} error=${req.error} payloadLen=${req.payload.length}`,
    );
    return;
  }

  const utilLabel =
    req.component === Component.Util ? utilCommandName(req.command) : `${req.component}/${req.command}`;

  const componentHandlers = handlers.get(req.component);
  if (componentHandlers) {
    const handler = componentHandlers.get(req.command);
    if (handler) {
      handler(req, session, (reply) => write(reply, `registered:${utilLabel}`));
      return;
    }
  }

  // Fallback to legacy handlers.
  // Empty array = handled with no wire reply (do NOT emptyDefault — empty ping
  // payload crashes FIFA; that bug fired when PING_SWALLOW returned []).
  const legacyReplies = handleBlazeRequestLegacy(req, session);
  if (legacyReplies) {
    for (const reply of legacyReplies) {
      write(reply, `legacy:${utilLabel}`);
    }
    return;
  }

  log("warn", "blaze", `Unhandled request: component=${req.component}, command=${req.command}`);

  // Default empty reply to prevent client hang (Message requests only)
  const reply = buildBlazePacket({
    component: req.component,
    command: req.command,
    msgNum: req.msgNum,
    msgType: MsgType.Reply,
    payload: Buffer.alloc(0),
    headerStyle: req.headerStyle,
  });
  write(reply, `emptyDefault:${utilLabel}`);
}
