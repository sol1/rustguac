# Themes

rustguac ships with a small set of built-in colour presets and lets you
add your own without recompiling. This page covers everything theme:
choosing a preset, overriding individual colours, and authoring a brand
new theme as a `.toml` file.

## Quick choices

- **Just want a different look?** Pick from the gear menu in the top right
  of any page. Your choice is stored per-browser (localStorage), so it
  follows you across sessions on that machine but doesn't affect anyone
  else.
- **Want to set the default for the whole deployment?** Add a `[theme]`
  block to `config.toml` (see below). Individual users can still override
  via the gear menu.
- **Want a custom palette or your org's brand colours?** Drop a `.toml`
  file into the themes directory. No recompile, no PR to the project.

## Built-in presets

| Name | Description |
|------|-------------|
| `aurora` | Default. Cool blues with a soft radial gradient backdrop. |
| `dark` | Classic dark mode (red primary, teal accent). |
| `light` | Bright neutral. |
| `high-contrast` | Maximum legibility, accessibility-friendly. |
| `terminal` | Monospaced green-on-black aesthetic. |
| `nord` | Cool greys + cyan, based on the Nord palette. |
| `corporate` | Muted business blues. |
| `jaguar` | Deep emerald + indigo. |

Plus any user-supplied themes you've dropped into the themes directory
(see [User-supplied themes](#user-supplied-themes) below).

## Setting the default in `config.toml`

The `[theme]` block in `config.toml` picks the default preset for new
users and lets you override individual colours on top of that preset.

```toml
[theme]
preset = "aurora"            # base preset; defaults to "aurora" if omitted
logo_url = "/logo.png"       # optional, replaces the rustguac logo
primary_color = "#003366"    # any of the per-field overrides below
```

When `[theme]` is absent entirely the default is the same as
`preset = "aurora"` with no overrides.

### Per-field overrides

Every colour in a theme can be overridden individually via the `[theme]`
block. The override wins; the preset provides the rest.

| Key | Description |
|-----|-------------|
| `primary_color` | Primary action colour (buttons, links) |
| `primary_hover` | Primary hover state |
| `accent_color` | Accent/secondary colour |
| `accent_hover` | Accent hover state |
| `bg_color` | Page background |
| `surface_color` | Card/panel backgrounds |
| `input_color` | Form input backgrounds |
| `text_color` | Primary text |
| `text_muted` | Secondary/muted text |
| `text_dim` | Tertiary/dim text |
| `text_on_primary` | Text on primary-coloured backgrounds |
| `border_color` | Borders and dividers |
| `btn_disabled` | Disabled button colour |
| `bg_pattern` | CSS background-image (gradient, pattern, or `"none"`) |
| `status_pending` / `status_active` / `status_completed` / `status_error` / `status_expired` | Session-state badge colours |
| `type_ssh_bg` / `type_ssh_fg` | SSH session-type badge |
| `type_rdp_bg` / `type_rdp_fg` | RDP session-type badge |
| `type_vnc_bg` / `type_vnc_fg` | VNC session-type badge |
| `type_web_bg` / `type_web_fg` | Web session-type badge |
| `type_vdi_bg` / `type_vdi_fg` | VDI session-type badge |
| `hop_bg` / `hop_fg` | Jump host badge |

All colour values are CSS colour strings (`"#003366"`, `"rgb(0,51,102)"`,
`"hsl(210 100% 20%)"`, anything CSS accepts).

### Example: corporate branding on top of a preset

```toml
site_title = "Acme Remote Console"

[theme]
preset = "light"
logo_url = "/acme-logo.png"
primary_color = "#003366"
accent_color = "#FF6600"
```

## User-supplied themes

Since v1.7.1 you can ship arbitrary themes as standalone files without
touching Rust or the project repo. Drop a `<name>.toml` file into
`<static_path>/themes/` (typically `/opt/rustguac/static/themes/`), restart
rustguac, and the theme appears in the gear-menu picker. Available to all
users; selectable as `preset = "<name>"` in `config.toml`.

### File format

A theme file is a flat TOML table with one entry per colour. The filename
(minus `.toml`) is the theme id. There is **no** `name` field inside the
file. Every field listed in the table below is required (the field names
match the per-field overrides above, but **without** the `_color` suffix
(e.g. `primary`, not `primary_color`); the sole exception is `bg_pattern`,
which defaults to `"none"` if omitted.

```toml
# /opt/rustguac/static/themes/acme-night.toml
primary          = "#003366"
primary_hover    = "#002244"
accent           = "#FF6600"
accent_hover     = "#CC4400"
bg               = "#0a0e1a"
surface          = "#141a2c"
input            = "#0f1422"
text             = "#e0e6f0"
text_muted       = "#a0a8b8"
border           = "#2a3045"
text_dim         = "#606878"
text_on_primary  = "#ffffff"
btn_disabled     = "#444a5c"
status_pending   = "#f0c040"
status_active    = "#22d3a0"
status_completed = "#888"
status_error     = "#ff5566"
status_expired   = "#666"
type_ssh_bg      = "#1b4332"
type_ssh_fg      = "#52b788"
type_rdp_bg      = "#3d1f00"
type_rdp_fg      = "#f0a050"
type_vnc_bg      = "#2d1b4e"
type_vnc_fg      = "#b07ff0"
type_web_bg      = "#1a1a4e"
type_web_fg      = "#7b8ff0"
type_vdi_bg      = "#0e2a2a"
type_vdi_fg      = "#2dd4bf"
hop_bg           = "#0d2818"
hop_fg           = "#34d399"
bg_pattern       = "none"
```

A complete example ships with rustguac at
`static/themes/catppuccin-macchiato.toml`. Copy it and tweak.

### Naming rules

Theme filenames (and therefore theme ids) must match
`[a-zA-Z0-9_-]{1,64}`. Anything outside that set (spaces, dots,
non-ASCII, control characters) is **rejected at load time with a log
warning** and the file is ignored. This keeps theme ids safe to render
unescaped in the UI picker, safe in log lines, and free of any
path-traversal or homoglyph mischief from crafted filenames.

### Overriding a built-in

If you create a file named after a built-in (`aurora.toml`,
`corporate.toml`, …) it **replaces** the built-in in the picker and in
`preset` resolution. This is the supported way to re-brand a built-in
without forking rustguac: edit your own `aurora.toml` rather than
patching the Rust source.

### Loading rules

- Loaded once at rustguac startup. Restart `rustguac` after adding,
  editing, or removing a theme file.
- Files must have a `.toml` extension to be loaded.
- Each file must contain all required colour fields. Files missing
  fields are skipped with a parse warning.
- Files with invalid TOML are skipped with a parse warning.
- Built-in themes are always loaded first; user themes are appended
  (or override a built-in with the same name).

### Where the themes directory lives

The themes directory is `<static_path>/themes/`. The `static_path` is
set in `config.toml`; defaults are:

| Install method | Default static_path |
|----------------|---------------------|
| `.deb` (Debian) | `/opt/rustguac/static/` |
| Docker image | `/opt/rustguac/static/` |
| `install.sh` (bare metal) | `/opt/rustguac/static/` |
| Cargo run from source | `./static/` |

For Docker, mount your themes directory over the in-image path:

```bash
docker run -v /etc/rustguac/themes:/opt/rustguac/static/themes:ro ...
```

## Per-user theme switching

The gear menu in the top right of every page lets each user pick from any
available theme. The choice persists in browser localStorage, so it
follows the user across sessions on that browser but doesn't affect
anyone else. The admin-configured `preset` is the default for users who
haven't picked one.
