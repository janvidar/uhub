// flood.js -- JavaScript port of mod_flood for mod_javascript.
//
// The hub detects floods (against its flood_ctl_* thresholds) and raises
// onFloodDetected; this script decides the action. It keeps a per-user strike
// counter and disconnects a user once the grace limit is reached. Operators are
// left alone unless operator_override=0.
//
//   plugin /usr/lib/uhub/mod_javascript.so "script=/etc/uhub/flood.js grace=3"

var grace = parseInt((uhub.config && uhub.config.grace) || "3", 10);
if (!(grace >= 1)) grace = 1;
var operatorOverride = !(uhub.config && uhub.config.operator_override === "0");

var strikes = new Map(); // connection id -> strike count

function isOperator(user) {
    var c = user.credentials;
    return c === "operator" || c === "super" || c === "admin";
}

uhub.onFloodDetected(function (user, type) {
    if (operatorOverride && isOperator(user))
        return uhub.ALLOW;

    var n = (strikes.get(user.id) || 0) + 1;
    strikes.set(user.id, n);

    if (n >= grace) {
        user.sendStatus(0, "Disconnected: repeated " + type + " flooding.");
        user.disconnect();
        return uhub.DENY; // handled; drop the offending message quietly
    }
    // Below the limit: let the hub apply its built-in drop + warning.
    return uhub.DEFAULT;
});

uhub.onUserLogout(function (user) {
    strikes.delete(user.id);
});
