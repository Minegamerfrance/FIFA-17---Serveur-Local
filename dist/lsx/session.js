import fs from "node:fs";
import path from "node:path";
function num(v, fallback) {
    if (typeof v === "number" && Number.isFinite(v))
        return v;
    if (typeof v === "string" && v.trim()) {
        const n = Number(v);
        if (Number.isFinite(n))
            return n;
    }
    return fallback;
}
export function loadLsxSession(explicitPath) {
    const candidates = [
        explicitPath,
        process.env.MNG_SESSION_FILE,
        process.env.LSX_SESSION_FILE,
        path.join(process.cwd(), "active-session.json"),
        path.join(process.env.LOCALAPPDATA ?? "", "MNGLauncher", "active-session.json"),
    ].filter((p) => Boolean(p && String(p).trim()));
    let raw = {};
    for (const file of candidates) {
        try {
            if (fs.existsSync(file)) {
                raw = JSON.parse(fs.readFileSync(file, "utf8"));
                break;
            }
        }
        catch (_) { }
    }
    const uid = num(raw.Uid ?? raw.uid, 1000000001);
    const personaId = num(raw.PersonaId ?? raw.personaId, 2000000001);
    const personaName = String(raw.PersonaName ?? raw.personaName ?? "LocalPlayer");
    const authCode = String(raw.AuthCode ?? raw.authCode ?? "LOCAL-FIFA17-AUTH");
    return {
        email: String(raw.Email ?? raw.email ?? `${personaName}@local`),
        personaName,
        uid,
        personaId,
        authCode,
        pctk: String(raw.Pctk ?? raw.pctk ?? `LOCAL-PCTK-${uid}`),
        skey: String(raw.Skey ?? raw.skey ?? `LOCAL-SKEY-${uid}`),
        contentId: String(process.env.LSX_CONTENT_ID ??
            raw.ContentId ??
            // FIFA17.exe sends this exact ContentId and MultiplayerId in its
            // natural LSX ChallengeResponse.  Do not use an Origin offer ID from
            // another game's SDK example here: Commerce entitlement ownership is
            // matched against this title identity after GetWalletBalance.
            "1027460"),
        displayName: String(raw.DisplayName ?? "FIFA 17"),
    };
}
//# sourceMappingURL=session.js.map