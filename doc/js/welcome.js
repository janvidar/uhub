// welcome.js -- JavaScript port of mod_welcome for mod_javascript.
//
// Sends a message-of-the-day to each user on login. The text comes from the
// plugin config (scripts have no filesystem access), e.g.:
//
//   plugin /usr/lib/uhub/mod_javascript.so "script=/etc/uhub/welcome.js motd=Welcome %n!"
//
// Supported substitutions in the motd text: %n = nick, %c = credentials, %% = %.

var motd = (uhub.config && uhub.config.motd) || "Welcome to the hub, %n!";

function expand(template, user) {
    return template.replace(/%[nc%]/g, function (m) {
        if (m === "%n") return user.nick;
        if (m === "%c") return user.credentials;
        return "%";
    });
}

uhub.onUserLogin(function (user) {
    user.sendMessage(expand(motd, user));
});
