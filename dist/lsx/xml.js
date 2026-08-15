function esc(s) {
    return s
        .replace(/&/g, "&amp;")
        .replace(/"/g, "&quot;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
}
export function wrapLsx(inner) {
    return `<LSX>${inner}</LSX>`;
}
export function eventChallenge(key, version = "1", build = "MNG-LSX-1") {
    return wrapLsx(`<Event sender="EALS"><Challenge key="${esc(key)}" version="${esc(version)}" build="${esc(build)}"/></Event>`);
}
export function responseChallengeAccepted(id, responseHex) {
    return wrapLsx(`<Response id="${esc(id)}" sender="EALS"><ChallengeAccepted response="${esc(responseHex)}"/></Response>`);
}
export function responseXml(id, sender, body) {
    return wrapLsx(`<Response id="${esc(id)}" sender="${esc(sender)}">${body}</Response>`);
}
export function eventXml(sender, body) {
    return wrapLsx(`<Event sender="${esc(sender)}">${body}</Event>`);
}
function success(sender) {
    return {
        sender,
        body: `<ErrorSuccess Description="" Code="0"/>`,
    };
}
/**
 * Build a protocol-correct Origin LSX response.
 *
 * The response sender is selected by facility (Utility, PI, XMPP, Commerce,
 * EALS or EbisuSDK); it must not simply echo Request.recipient. Older Origin
 * SDK clients use the sender and response element type when dispatching the
 * completion callback.
 */
export function buildResponse(request, session) {
    const { type, attributes } = request;
    const now = new Date().toISOString().replace(/\.\d{3}Z$/, "");
    switch (type) {
        case "GetInternetConnectedState":
            return {
                sender: "Utility",
                body: `<InternetConnectedState connected="1"/>`,
            };
        case "GetAuthCode":
            return {
                sender: "Utility",
                body: `<AuthCode value="${esc(session.authCode)}"/>`,
            };
        case "GetAuthToken":
            return {
                sender: "Utility",
                body: `<AuthToken value="${esc(session.authCode)}"/>`,
            };
        case "CheckPermission":
            // Origin SDK dispatches this request by response element type. A generic
            // ErrorSuccess leaves the permission callback unresolved even with Code=0.
            // FIFA uses at least MULTIPLAYER while entering its online/FUT flow.
            return {
                sender: "EbisuSDK",
                body: `<CheckPermissionResponse Access="GRANTED"/>`,
            };
        case "GetBlockList":
            return {
                sender: "EbisuSDK",
                body: `<GetBlockListResponse Return="Success"/>`,
            };
        case "GetGameInfo": {
            const infoId = (attributes.GameInfoId ?? "").toUpperCase();
            let value = "ar_SA,cs_CZ,de_DE,en_US,es_ES,es_MX,fr_FR,it_IT,ja_JP,ko_KR,pl_PL,pt_BR,ru_RU,zh_CN,zh_TW";
            if (infoId === "FREETRIAL")
                value = "false";
            else if (infoId === "UPTODATE")
                value = "true";
            else if (infoId === "INSTALLED_LANGUAGE")
                value = "fr_FR";
            return {
                sender: "EbisuSDK",
                body: `<GetGameInfoResponse GameInfo="${esc(value)}"/>`,
            };
        }
        case "GetSetting": {
            const settingId = (attributes.SettingId ?? "").toUpperCase();
            let value = "false";
            if (settingId === "ENVIRONMENT")
                value = "production";
            else if (settingId === "LANGUAGE")
                value = "fr_FR";
            else if (settingId === "IS_IGO_AVAILABLE")
                value = "true";
            else if (settingId === "IS_IGO_ENABLED")
                value = "true";
            return {
                sender: "EbisuSDK",
                body: `<GetSettingResponse Setting="${value}"/>`,
            };
        }
        case "SetDownloaderUtilization":
            return success("PI");
        case "GetProfile":
            return {
                sender: "EbisuSDK",
                body: `<GetProfileResponse UserIndex="0" UserId="${session.uid}" PersonaId="${session.personaId}" ` +
                    `Persona="${esc(session.personaName)}" AvatarId="0" Country="FR" IsUnderAge="false" ` +
                    `IsSubscriber="true" IsTrialSubscriber="false" SubscriberLevel="1" GeoCountry="FR" ` +
                    `CommerceCountry="FR" CommerceCurrency="EUR" IsSteamSubscriber="false"/>`,
            };
        case "GetAllGameInfo":
            return {
                sender: "EbisuSDK",
                body: `<GetAllGameInfoResponse UpToDate="true" Languages="fr_FR,en_US" FreeTrial="false" ` +
                    `FullGamePurchased="true" FullGameReleased="true" FullGameReleaseDate="2016-09-27T00:00:00" ` +
                    `Expiration="0000-00-00T00:00:00" SystemTime="${esc(now)}" HasExpiration="false" ` +
                    `InstalledVersion="0" InstalledLanguage="fr_FR" AvailableVersion="0.0.0.0" ` +
                    `DisplayName="${esc(session.displayName)}" MaxGroupSize="22" EntitlementSource="ORIGIN"/>`,
            };
        case "QueryEntitlements":
            {
                const requestedGroup = attributes.Group || "FIFA17PCBoxContent";
                // As in the working FIFA 14 contract, GNAM/Group is the request filter
                // while EntitlementTag identifies the actual FUT content grant.
                const entitlementTag = "FIFA17PCFUTContentUnlocks";
                return {
                    sender: "Commerce",
                    body: `<QueryEntitlementsResponse>` +
                        `<Entitlements GrantDate="${esc(now)}" ResourceId="${esc(session.contentId)}" ` +
                        `UseCount="0" EntitlementId="LOCAL-FIFA17" Expiration="0000-00-00T00:00:00" ` +
                        `Type="DEFAULT" Source="ORIGIN" LastModifiedDate="${esc(now)}" Group="${esc(requestedGroup)}" ` +
                        `ItemId="${esc(session.contentId)}" EntitlementTag="${esc(entitlementTag)}" Version="1"/>` +
                        `</QueryEntitlementsResponse>`,
                };
            }
        case "QueryOffers":
            // Origin SDK v3 expects a fully shaped Offer entry here.  Returning an
            // empty QueryOffersResponse leaves FIFA 17's commerce bootstrap without
            // an object to complete, immediately before the permanent loading card.
            return {
                sender: "Commerce",
                body: `<QueryOffersResponse>` +
                    `<Offer Currency="_FF" bHidden="false" UseEndDate="0000-00-00T00:00:00" ` +
                    `bIsDiscounted="false" ImageId="" Description="FIFA 17 local online content" ` +
                    `LocalizedOriginalPrice="0" GameDistributionSub="" InventorySold="-1" ` +
                    `Name="FIFA 17 Online Services" Price="0" InventoryCap="-1" OriginalPrice="0" ` +
                    `PlayableDate="2016-09-27T00:00:00" DownloadSize="0" ` +
                    `DownloadDate="2016-09-27T00:00:00" LocalizedPrice="0" bCanPurchase="false" ` +
                    `InventoryAvailable="-1" PurchaseDate="${esc(now)}" bIsOwned="true" ` +
                    `Type="Extra Content" OfferId="${esc(session.contentId)}"/>` +
                    `</QueryOffersResponse>`,
            };
        case "GetWalletBalance":
            return {
                sender: "Commerce",
                body: `<GetWalletBalanceResponse Balance="0"/>`,
            };
        case "IsProgressiveInstallationAvailable":
            return {
                sender: "PI",
                body: `<IsProgressiveInstallationAvailableResponse Available="false"/>`,
            };
        case "GoOnline":
        case "Login":
            return success("EALS");
        case "SetPresence":
        case "SubscribePresence":
        case "UnsubscribePresence":
            return success("XMPP");
        case "QueryFriends":
            return { sender: "XMPP", body: `<QueryFriendsResponse/>` };
        case "QueryPresence":
            return { sender: "XMPP", body: `<QueryPresenceResponse/>` };
        case "GetPresence":
            return {
                sender: "XMPP",
                body: `<GetPresenceResponse UserId="${session.uid}" Presence="ONLINE" Title="${esc(session.displayName)}" ` +
                    `TitleId="${esc(session.contentId)}" MultiplayerId="" RichPresence="" ` +
                    `GamePresence="" Group="" GroupId="" SessionId="local"/>`,
            };
        case "QueryImage":
            return { sender: "EbisuSDK", body: `<QueryImageResponse Result="0"/>` };
        case "GetUtcTime":
            return {
                sender: "EbisuSDK",
                body: `<GetUtcTimeResponse Time="${esc(now)}"/>`,
            };
        case "GetSettings":
            return {
                sender: "EbisuSDK",
                body: `<GetSettingsResponse Language="fr_FR" Environment="production" ` +
                    `IsIGOAvailable="false" IsIGOEnabled="false" IsTelemetryEnabled="false" ` +
                    `IsAutomaticGameUpdatesEnabled="false" IsManualOffline="false"/>`,
            };
        case "GetConfig":
            return {
                sender: "EbisuSDK",
                body: `<GetConfigResponse>` +
                    `<Service Facility="SDK" Name="EbisuSDK"/>` +
                    `<Service Facility="PROFILE" Name="EbisuSDK"/>` +
                    `<Service Facility="PRESENCE" Name="XMPP"/>` +
                    `<Service Facility="FRIENDS" Name="XMPP"/>` +
                    `<Service Facility="COMMERCE" Name="Commerce"/>` +
                    `<Service Facility="RECENTPLAYER" Name="EbisuSDK"/>` +
                    `<Service Facility="IGO" Name="EbisuSDK"/>` +
                    `<Service Facility="MISC" Name="EbisuSDK"/>` +
                    `<Service Facility="LOGIN" Name="EALS"/>` +
                    `<Service Facility="UTILITY" Name="Utility"/>` +
                    `<Service Facility="XMPP" Name="XMPP"/>` +
                    `<Service Facility="CHAT" Name="XMPP"/>` +
                    `<Service Facility="IGO_EVENT" Name="EbisuSDK"/>` +
                    `<Service Facility="EALS_EVENTS" Name="EALS"/>` +
                    `<Service Facility="LOGIN_EVENT" Name="EbisuSDK"/>` +
                    `<Service Facility="PROFILE_EVENT" Name="EbisuSDK"/>` +
                    `<Service Facility="PRESENCE_EVENT" Name="XMPP"/>` +
                    `<Service Facility="FRIENDS_EVENT" Name="XMPP"/>` +
                    `<Service Facility="COMMERCE_EVENT" Name="Commerce"/>` +
                    `<Service Facility="DOWNLOAD_EVENT" Name="EbisuSDK"/>` +
                    `<Service Facility="PERMISSION" Name="EbisuSDK"/>` +
                    `<Service Facility="RESOURCES" Name="EbisuSDK"/>` +
                    `<Service Facility="BLOCKED_USERS" Name="EbisuSDK"/>` +
                    `<Service Facility="BLOCKED_USER_EVENT" Name="EbisuSDK"/>` +
                    `<Service Facility="GET_USERID" Name="EbisuSDK"/>` +
                    `<Service Facility="ONLINE_STATUS_EVENT" Name="EbisuSDK"/>` +
                    `<Service Facility="PROGRESSIVE_INSTALLATION" Name="PI"/>` +
                    `<Service Facility="PROGRESSIVE_INSTALLATION_EVENT" Name="PI"/>` +
                    `<Service Facility="CONTENT" Name="EbisuSDK"/>` +
                    `</GetConfigResponse>`,
            };
        default:
            return null;
    }
}
export function onlineStatusEvent(isOnline) {
    return eventXml("EbisuSDK", `<OnlineStatusEvent isOnline="${isOnline ? "1" : "0"}"/>`);
}
export function currentUserPresenceEvent(session) {
    return eventXml("EbisuSDK", `<CurrentUserPresenceEvent UserId="${session.uid}" Presence="ONLINE" Title="${esc(session.displayName)}" ` +
        `TitleId="${esc(session.contentId)}" MultiplayerId="" RichPresence="" GamePresence="" ` +
        `SessionId="local" Group="" GroupId=""/>`);
}
export function profileEvent(session) {
    return eventXml("EbisuSDK", `<ProfileEvent Changed="EAID" UserId="${session.uid}"/>`);
}
/** Extract request id + first child element name from LSX Request XML. */
export function parseRequestMeta(xml) {
    const idM = xml.match(/<Request[^>]*\bid="([^"]*)"/i);
    const recipM = xml.match(/<Request[^>]*\brecipient="([^"]*)"/i);
    // First element inside Request after attributes
    const bodyM = xml.match(/<Request\b[^>]*>\s*<([A-Za-z0-9_]+)([^>]*)/i);
    const attributes = {};
    const attrText = bodyM?.[2] ?? "";
    for (const match of attrText.matchAll(/([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]*)"/g)) {
        attributes[match[1]] = match[2];
    }
    return {
        id: idM?.[1] ?? "0",
        type: bodyM?.[1] ?? "Unknown",
        recipient: recipM?.[1] ?? "EbisuSDK",
        attributes,
    };
}
/** Origin SDK login-complete event routed through the LOGIN_EVENT facility. */
export function loginEvent() {
    return eventXml("EbisuSDK", `<Login IsLoggedIn="true" UserIndex="0" LoginReasonCode="ALREADY_ONLINE"/>`);
}
export function parseChallengeResponse(xml) {
    if (!/ChallengeResponse/i.test(xml))
        return null;
    const idM = xml.match(/<Request[^>]*\bid="([^"]*)"/i);
    const keyM = xml.match(/<ChallengeResponse[^>]*\bkey="([^"]*)"/i);
    const respM = xml.match(/<ChallengeResponse[^>]*\bresponse="([^"]*)"/i);
    if (!keyM || !respM)
        return null;
    return {
        id: idM?.[1] ?? "0",
        key: keyM[1],
        response: respM[1],
    };
}
//# sourceMappingURL=xml.js.map