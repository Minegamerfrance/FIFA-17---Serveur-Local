import express from "express";
export declare function startFutApi(tls: {
    key: Buffer;
    cert: Buffer;
}): express.Express;
