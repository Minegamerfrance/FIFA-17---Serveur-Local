export type LogLevel = "debug" | "info" | "warn" | "error";
/** Same style as Frida probe: === log sauvé: <path> === */
export declare function announceSessionLog(): void;
/** Absolute path of the current session log file, or null if LOG_TO_FILE=0. */
export declare function getSessionLogPath(): string | null;
export declare function log(level: LogLevel, scope: string, message: string, extra?: unknown): void;
export declare function dumpPacket(label: string, buf: Buffer): void;
