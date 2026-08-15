import assert from "node:assert/strict";
import { buildResponse, parseRequestMeta } from "../src/lsx/xml.js";
import type { LsxSession } from "../src/lsx/session.js";

const session: LsxSession = {
  email: "player@local",
  personaName: "LocalPlayer",
  uid: 1000000001,
  personaId: 2000000001,
  authCode: "LOCAL-AUTH",
  pctk: "LOCAL-PCTK",
  skey: "LOCAL-SKEY",
  contentId: "1027460",
  displayName: "FIFA 17",
};

function resolve(xml: string) {
  const meta = parseRequestMeta(xml);
  const response = buildResponse(meta, session);
  assert.ok(response, `missing response for ${meta.type}`);
  return { meta, response };
}

const downloader = resolve(
  '<LSX><Request recipient="PI" id="13"><SetDownloaderUtilization Utilization="1"/></Request></LSX>',
);
assert.equal(downloader.meta.attributes.Utilization, "1");
assert.equal(downloader.response.sender, "PI");
assert.match(downloader.response.body, /ErrorSuccess/);

const environment = resolve(
  '<LSX><Request recipient="EbisuSDK" id="14"><GetSetting SettingId="ENVIRONMENT"/></Request></LSX>',
);
assert.equal(environment.response.sender, "EbisuSDK");
assert.match(environment.response.body, /Setting="production"/);

const trial = resolve(
  '<LSX><Request recipient="EbisuSDK" id="15"><GetGameInfo GameInfoId="FREETRIAL"/></Request></LSX>',
);
assert.match(trial.response.body, /GameInfo="false"/);

const internet = resolve(
  '<LSX><Request recipient="Utility" id="16"><GetInternetConnectedState version="1"/></Request></LSX>',
);
assert.equal(internet.response.sender, "Utility");
assert.match(internet.response.body, /connected="1"/);

const permission = resolve(
  '<LSX><Request recipient="EbisuSDK" id="17"><CheckPermission UserId="1000000001" PermissionId="MULTIPLAYER"/></Request></LSX>',
);
assert.equal(permission.meta.attributes.PermissionId, "MULTIPLAYER");
assert.equal(permission.response.sender, "EbisuSDK");
assert.equal(permission.response.body, '<CheckPermissionResponse Access="GRANTED"/>');

const igoAvailable = resolve(
  '<LSX><Request recipient="EbisuSDK" id="18"><GetSetting SettingId="IS_IGO_AVAILABLE"/></Request></LSX>',
);
assert.match(igoAvailable.response.body, /Setting="true"/);

console.log("LSX response mapping OK: ids 13 -> 18");
