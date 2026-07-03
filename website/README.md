# uhub website

Static site for uhub, built by a small dependency-free Python script.

## Build

```sh
cd website
python3 build.py
```

This regenerates every page in `uhub-static/` (the deploy artifact, served by
copying). Re-running is idempotent.

## Layout

- `templates/base.html` — the page skeleton (`<head>`, body wrapper, script).
- `templates/partials/` — shared chrome: `header.html`, `footer.html`,
  `doc-sidebar.html`. Edit the nav or sidebar **once** here, then rebuild.
- `content/` — one fragment per page: a short `key: value` front-matter block
  (`title`, `description`, `layout`, `nav`, `sidebar`) followed by the page
  body. `content/doc/plugins/index.html` mirrors the output path.
- `content/doc/config.html` holds only the intro + search toolbar and a
  `{config_reference}` marker; the directive list is generated (see below).
- `content/doc/_acl-directives.html` — the hand-written `users.conf` ACL block
  (leading `_` = not a page; included by the config-reference generator).
- `uhub-static/assets/` — CSS/JS/images, static (not touched by the build).

## Config reference generation

`doc/config.html` is generated from `../src/core/config.xml` — the same schema
the C config loader uses. `build.py` imports the `Option` parser from
`../src/core/config.py`, groups the options (taxonomy in the `GROUPS` table in
`build.py`), and emits the `<details>` directives. Any option not matched by a
group lands in a trailing "Other" group, so a newly added directive always
appears. To add a config option, edit `config.xml` only and rebuild.

## Tokens (in templates/partials)

- `{root:path}` → the page-relative path to `path` (depth-aware).
- `{active:key}` → ` class="active"` when the page's `nav`/`sidebar` matches.
- `{year}` → the current year (footer copyright).
