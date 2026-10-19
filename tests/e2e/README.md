# End-to-end tests

Playwright specs that drive the real pages in `static/` against a stubbed
API. Nothing here needs Vault, guacd, Docker or a browser session: `serve.mjs`
serves the static tree over HTTP and every spec installs `lib/api.mjs`, which
answers `/api/*` from a small fixture address book (two named tenants and
twenty generic ones, two sessions, two recordings) and records every request
the page makes so a spec can assert on what was sent.

```sh
cd tests/e2e
npm ci
npx playwright install chromium   # once
npm test                          # all specs
npx playwright test specs/global-search.spec.mjs
npx playwright test --ui          # step through a spec
```

`PW_CHROMIUM=/path/to/chrome` runs against an already installed Chromium
instead of the one Playwright downloads. CI runs the suite in the `e2e` job.

One spec per change, named after the branch that introduced it:

| spec | pins |
|---|---|
| `tables-1710` | #252: no horizontal overflow at 1710px on Connections, Recordings and Reports, with short and with long unbreakable names |
| `connections-sidebar` | #254: independent sidebar scroll, selected row marked and kept in view |
| `connections-folder-filter` | #254: live filter box, ARIA tree, arrow keys, `f` shortcut |
| `connections-app-shell` | #254: clipped body, two scroll panes, folder change scrolls the pane not the page |
| `role-nav` | one nav on every page, gated by `data-role-level` |
| `sessions-adhoc-modal` | #295: Sessions has no ad-hoc form or button of its own; the global button there opens the editor on Connections |
| `adhoc-button` | #295: search.js's Connect to a host beside the box on every search page, for poweruser and admin, in place on Connections and via `#adhoc` elsewhere; never for operator, viewer, signed out or on the login page; gone on expiry and logout; shown without Vault; API key confirmed first |
| `facet-filters` | shared facets narrow lists, persist, combine with search |
| `folder-display-name` | display name over the key, modal field round-trips |
| `themed-dialogs` | `rgConfirm`/`rgAlert` replace native dialogs |
| `global-search` | `/` opens the overlay on every signed-in page, folder view untouched; nothing on the login page, for anonymous or viewer callers, or from a previous login's cache |
| `search-under-modals` | a page modal (the ad-hoc editor included) covers the search box |
| `zero-click-fullscreen` | #257: same-tab iframe sized from the measured viewport |
| `connections-adhoc` | #295: Connect to a host opens the entry editor in ad-hoc mode (no name, Connect for Save, entry-only options hidden for non-admins), offers the caller's credential variable names, posts to `/api/addressbook/adhoc/connect` and never `/api/sessions`; ephemeral keypair; missing variable named; admin Save as entry keeps `$var` references; works without Vault and from `#adhoc`; no button for operators |
| `recordings-mp4` | #241: the mp4 button converts, shows progress and downloads; refused while live; hidden without server support |
| `multi-protocol-entries` | #296: one row per host with a badge per protocol, Connect for the primary and a menu for the rest; Host box and protocol tabs; an old single-protocol entry saves as one protocol |

The fixture suppresses the first-visit onboarding tour (`options.onboarding`
re-enables it) and defaults to the admin role; pass `role` to test gating.
