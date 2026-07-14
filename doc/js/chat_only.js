// chat_only.js -- JavaScript port of mod_chat_only for mod_javascript.
//
// Turns the hub into a chat-only hub: searches, search results and
// peer-to-peer connection setup are denied. Each user is warned once per
// category. Operators (and above) are exempt unless operator_override=0.
//
//   plugin /usr/lib/uhub/mod_javascript.so "script=/etc/uhub/chat_only.js"

var operatorOverride = !(uhub.config && uhub.config.operator_override === "0");

// Per-user "already warned" state, keyed by the stable connection id. Cleaned
// up on logout (see below).
var warned = new Map();

function isOperator(user) {
    var c = user.credentials;
    return c === "operator" || c === "super" || c === "admin";
}

function denyOnce(user, key, message) {
    if (operatorOverride && isOperator(user))
        return uhub.ALLOW;
    var seen = warned.get(user.id) || {};
    if (!seen[key]) {
        user.sendStatus(0, message);
        seen[key] = true;
        warned.set(user.id, seen);
    }
    return uhub.DENY;
}

uhub.onSearch(function (user) {
    return denyOnce(user, "search", "Searching is disabled. This is a chat only hub.");
});

uhub.onSearchResult(function () {
    return uhub.DENY;
});

uhub.onP2PConnect(function (user) {
    return denyOnce(user, "connect", "Connection setup denied. This is a chat only hub.");
});

uhub.onP2PRevConnect(function (user) {
    return denyOnce(user, "connect", "Connection setup denied. This is a chat only hub.");
});

uhub.onUserLogout(function (user) {
    warned.delete(user.id);
});
