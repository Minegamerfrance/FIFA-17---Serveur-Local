import net from "node:net";
import { type LsxSession } from "./session.js";
export type LsxServerOptions = {
    host?: string;
    port?: number;
    session?: LsxSession;
    /** If true, refuse to start when port is already bound. */
    failIfBusy?: boolean;
};
export declare function startOriginLsxServer(opts?: LsxServerOptions): Promise<net.Server>;
