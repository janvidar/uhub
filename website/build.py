#!/usr/bin/env python3
"""
Static site builder for the uhub website.

Assembles every page from templates/ + content/ fragments into uhub-static/,
and generates the configuration reference (doc/config.html) directly from the
authoritative src/core/config.xml so it never drifts from the hub.

Usage:  python3 build.py        # from the website/ directory

No third-party dependencies. Assets (uhub-static/assets/) are static and left
untouched; this script only (re)writes the HTML pages.
"""
import os
import re
import sys
from datetime import datetime
from xml.dom import minidom

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
CONTENT = os.path.join(HERE, "content")
TEMPLATES = os.path.join(HERE, "templates")
OUT = os.path.join(HERE, "uhub-static")
CONFIG_XML = os.path.join(REPO, "src", "core", "config.xml")

# Reuse the hub's own config.xml parser (the Option class) so the website and
# the C config loader read the exact same schema. Don't litter src/core with a
# __pycache__ from importing it.
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.join(REPO, "src", "core"))
import config as hubconfig  # noqa: E402  (Option class; __main__ guard keeps it inert)


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def strip_tags(s):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s or "")).strip()


def esc_attr(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


def esc_code(s):
    # entity-escape a value shown inside <code>, matching the hand-written style
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))


# --------------------------------------------------------------------------
# configuration reference generation (from config.xml)
# --------------------------------------------------------------------------

def names(*ns):
    s = set(ns)
    return lambda n: n in s


def prefixes(*ps):
    return lambda n: any(n.startswith(p) for p in ps)


def either(*fns):
    return lambda n: any(f(n) for f in fns)


# Ordered editorial taxonomy. Anything not matched lands in a trailing "Other"
# group, so a newly added option always shows up (just ungrouped until curated).
ACL_MARKER = "__ACL__"
GROUPS = [
    ("Server & network", names("server_port", "server_bind_addr",
        "server_listen_backlog", "server_alt_ports", "server_reuseport")),
    ("Hub options", names("hub_enabled", "hub_name", "hub_description",
        "max_users", "registered_users_only", "register_self",
        "chat_is_privileged", "obsolete_clients", "low_bandwidth_mode",
        "show_banner", "show_banner_sys_info", "redirect_addr")),
    ("Hub information", names("hub_address", "hub_website", "hub_network",
        "hub_owner", "reg_server_url")),
    ("Limits", prefixes("limit_")),
    ("Flood control", prefixes("flood_ctl_")),
    ("TLS", prefixes("tls_")),
    ("Metrics", prefixes("metrics_")),
    ("Federation & scaling", either(
        names("workers", "worker_socket_dir", "auth_proxy", "dns_thread_pool_size"),
        prefixes("link_", "node_", "hbri_"))),
    ("Files & buffers", names("file_acl", "file_plugins", "max_recv_buffer",
        "max_send_buffer", "max_send_buffer_soft", "max_chat_history",
        "max_logout_log")),
    (ACL_MARKER, None),
    ("Message strings", prefixes("msg_")),
]


def type_display(o):
    if o.otype == "boolean":
        return "boolean"
    if o.otype == "int":
        if o.check_min and o.check_max:
            return "number (%s–%s)" % (o.check_min, o.check_max)
        if o.check_min:
            return "number ≥ %s" % o.check_min
        if o.check_max:
            return "number ≤ %s" % o.check_max
        return "number"
    if o.otype == "file":
        return "file"
    return "String"


def default_display(o):
    if o.otype == "boolean":
        return "yes" if o.default in ("1", "yes", "true") else "no"
    if o.is_string:
        return '"%s"' % o.default
    return o.default


def badge(o):
    if o.otype == "message":
        return "string"
    return "default: " + esc_code(default_display(o))


def data_desc(o):
    d = strip_tags(o.short) or strip_tags(o.description)
    if len(d) > 200:
        d = d[:197].rstrip() + "…"
    return esc_attr(d)


def example_cell(ex):
    ex = ex.strip()
    if "<" in ex:            # rich example already carries its own markup
        return ex
    return "<code>%s</code>" % esc_code(ex)


def render_option(o):
    rows = []
    desc_html = (o.description or o.short or "").strip() or strip_tags(o.short)
    rows.append("<tr><th>Description</th><td>%s</td></tr>" % desc_html)
    rows.append("<tr><th>Type</th><td>%s</td></tr>" % type_display(o))
    rows.append("<tr><th>Default</th><td><code>%s</code></td></tr>"
                % esc_code(default_display(o)))
    if o.since:
        rows.append("<tr><th>Since</th><td>uhub %s</td></tr>" % o.since.strip())
    if o.syntax and o.syntax.strip():
        rows.append("<tr><th>Syntax</th><td>%s</td></tr>" % o.syntax.strip())
    if o.example and o.example.strip():
        rows.append("<tr><th>Example</th><td>%s</td></tr>" % example_cell(o.example))

    body = "\n".join("\t\t\t\t\t\t" + r for r in rows)
    return (
        '\t\t\t\t<details class="directive" data-name="%s" data-desc="%s">\n'
        '\t\t\t\t\t<summary>%s<span class="badge">%s</span></summary>\n'
        '\t\t\t\t\t<div class="directive-body"><table>\n'
        '%s\n'
        '\t\t\t\t\t</table></div>\n'
        '\t\t\t\t</details>'
        % (o.name, data_desc(o), o.name, badge(o), body)
    )


def render_group(title, details_html):
    return ('\t\t\t<div class="config-group">\n'
            '\t\t\t\t<h2>%s</h2>\n'
            '%s\n'
            '\t\t\t</div>' % (title, details_html))


def build_config_reference():
    doc = minidom.parse(CONFIG_XML)
    options = [hubconfig.Option(n) for n in doc.getElementsByTagName("option")]

    buckets = {title: [] for title, _ in GROUPS}
    other = []
    for o in options:
        for title, test in GROUPS:
            if test is not None and test(o.name):
                buckets[title].append(o)
                break
        else:
            other.append(o)

    acl_fragment = read(os.path.join(CONTENT, "doc", "_acl-directives.html")).rstrip("\n")

    out = []
    for title, _ in GROUPS:
        if title == ACL_MARKER:
            out.append(acl_fragment)
            continue
        opts = buckets[title]
        if not opts:
            continue
        details = "\n".join(render_option(o) for o in opts)
        out.append(render_group(title, details))
    if other:
        print("  note: %d option(s) had no group and went to 'Other': %s"
              % (len(other), ", ".join(o.name for o in other)))
        details = "\n".join(render_option(o) for o in other)
        out.append(render_group("Other", details))

    covered = sum(len(v) for v in buckets.values()) + len(other)
    print("  config reference: %d directives across %d groups"
          % (covered, sum(1 for t, _ in GROUPS if t != ACL_MARKER and buckets[t]) + (1 if other else 0)))
    return "\n".join(out)


# --------------------------------------------------------------------------
# page rendering
# --------------------------------------------------------------------------

BASE = read(os.path.join(TEMPLATES, "base.html"))
HEADER = read(os.path.join(TEMPLATES, "partials", "header.html"))
FOOTER = read(os.path.join(TEMPLATES, "partials", "footer.html"))
SIDEBAR = read(os.path.join(TEMPLATES, "partials", "doc-sidebar.html"))
YEAR = str(datetime.now().year)

DOC_WRAPPER = (
    '<div class="container doc-layout">\n'
    '\t<aside class="doc-sidebar">\n'
    '{sidebar}\n'
    '\t</aside>\n'
    '\n'
    '\t<main class="doc-content">\n'
    '\t\t<div class="prose">\n'
    '{prose}\n'
    '\t\t</div>\n'
    '\t</main>\n'
    '</div>'
)


def parse_fragment(text):
    head, _, body = text.partition("\n---\n")
    meta = {}
    for line in head.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            meta[k.strip()] = v.strip()
    return meta, body.rstrip("\n")


def resolve_tokens(text, page_dir, active_keys):
    text = text.replace("{year}", YEAR)
    text = re.sub(r"\{active:([^}]*)\}",
                  lambda m: ' class="active"' if m.group(1) in active_keys else "",
                  text)
    text = re.sub(r"\{root:([^}]*)\}",
                  lambda m: os.path.relpath(m.group(1), page_dir).replace(os.sep, "/"),
                  text)
    return text


def render_page(relpath, text, config_reference):
    meta, body = parse_fragment(text)
    page_dir = os.path.dirname(relpath) or "."
    active_keys = set()
    if meta.get("nav"):
        active_keys.add(meta["nav"])
    if meta.get("sidebar"):
        active_keys.add(meta["sidebar"])

    if relpath == os.path.join("doc", "config.html"):
        body = body.replace("{config_reference}", config_reference)

    if meta.get("layout") == "doc":
        content = DOC_WRAPPER.replace("{sidebar}", SIDEBAR).replace("{prose}", body)
    else:
        content = body

    page = (BASE
            .replace("{title}", meta["title"])
            .replace("{description}", meta["description"])
            .replace("{header}", HEADER)
            .replace("{content}", content)
            .replace("{footer}", FOOTER))
    return resolve_tokens(page, page_dir, active_keys)


def main():
    print("Building uhub website...")
    config_reference = build_config_reference()

    count = 0
    for root, _, files in os.walk(CONTENT):
        for fn in sorted(files):
            if not fn.endswith(".html") or fn.startswith("_"):
                continue
            src = os.path.join(root, fn)
            rel = os.path.relpath(src, CONTENT)
            out = render_page(rel, read(src), config_reference)
            dest = os.path.join(OUT, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as f:
                f.write(out)
            count += 1
    print("  wrote %d pages to %s" % (count, os.path.relpath(OUT, os.getcwd())))


if __name__ == "__main__":
    main()
