# The Hunter's Codex

A personal, living bug bounty checklist — static site, built for GitHub Pages.
No build step, no backend, no dependencies beyond two Google Fonts and a system
monospace fallback. Open `index.html` locally and it works exactly as it will
once deployed.

## Deploy to GitHub Pages

1. Create a new repo (e.g. `hunters-codex`) and push everything in this folder
   to its `main` branch, preserving the structure as-is.
2. In the repo: **Settings → Pages → Source → Deploy from a branch → `main` /
   `root`**.
3. Your site is live at `https://<your-username>.github.io/hunters-codex/`
   within a minute or two.

That's it — every link in the site is a relative path, so it works identically
whether it's served from a repo subpath (`username.github.io/repo-name/`) or a
custom domain root.

## Structure

```
index.html                       → animated home page
get-started.html                 → methodology, severity legend, ground rules
categories/
  low-hanging-fruits-1.html      → page shell for Part 1 (7 checks)   — realm: hulk
  low-hanging-fruits-2.html      → page shell for Part 2 (6 checks)   — realm: ironman
  low-hanging-fruits-3.html      → page shell for Part 3 (4 checks)   — realm: wakanda
  broken-access-control.html     → CSRF + IDOR/BOLA (2 checks)        — realm: thor
  security-misconfiguration.html → Subdomain takeover (1 check)       — realm: loki
assets/
  css/style.css                  → the entire visual theme, one file
  js/app.js                      → nav, realm canvas, card renderer, progress bar, filter, reveal
  js/data-lhf1.js                → content for Part 1 (one JS object per entry)
  js/data-lhf2.js                → content for Part 2
  js/data-lhf3.js                → content for Part 3
  js/data-access-control.js      → content for Broken Access Control
  js/data-subdomain-takeover.js  → content for Security Misconfiguration
```

Each category page is a thin shell: it loads its `data-*.js` file, then calls
`Codex.renderVulnList('vuln-list', LHF1, 'low-hanging-fruits-1')` to build the
accordion cards from that data. All the actual content lives in the data
files — the HTML shells never need touching once a new entry is added to the
right array.

## Adding a new entry to an existing directory

Open the matching `assets/js/data-lhf*.js` file and append a new object to the
array, following the shape already used by every other entry:

```js
{
  id: "unique-kebab-case-id",       // becomes the <details> element's id
  title: "Human Readable Title",
  category: "Short Category Label",
  severity: "critical|high|medium|low|info",
  descriptionHTML: `...`,
  impactHTML: `...`,
  severityHTML: `...`,
  stepsHTML: `...`,
  treeHTML: `...`,                  // optional — a decision-tree diagram, see below
  burpHTML: `...`,                  // optional — a numbered Burp Suite walkthrough
  extraHTML: `...`,                 // optional — omit the key entirely to skip the section
  reportYesHTML: `...`,
  reportNoHTML: `...`
}
```

`treeHTML` and `burpHTML` render (in that order) right after "Steps to Reproduce" and before "Additional Methodology & Tools" — both are plain optional keys, same as `extraHTML`; omit either to skip that section entirely. See `data-access-control.js`'s CSRF entry for a full example of both.

For a decision tree, nest `.tree` / `.tree-q` / `.tree-branch` / `.tree-opt.tree-yes` (or `.tree-no`) / `.tree-sub` the way the three existing trees do — it's an outline-indentation component (left borders, not drawn connector lines), so it never breaks on wrap and nests to any depth safely.

Every `*HTML` field is raw HTML inside a JS template literal (backticks) — use
`<h4>`, `<ul>`, `<pre><code>`, `<div class="dork-list">` (one `<code>` per
line for a list of dorks/filenames) and `<div class="tool-row">` (for a
tool-name + usage line) exactly like the existing entries do, and the shared
stylesheet will pick up the formatting automatically. Escape any literal
`<`/`>` inside example payloads as `&lt;`/`&gt;` so they render as visible
text instead of being parsed as HTML. If a payload example needs a literal
`${...}` inside a template literal, escape the dollar sign as `\${...}` or it
will be evaluated as JavaScript interpolation instead of shown as text.

## Adding a whole new directory

1. Duplicate `assets/js/data-lhf1.js` → `assets/js/data-X.js`, rename the
   exported array (e.g. `var ACCESS_CONTROL = [...]`), and replace the
   entries.
2. Duplicate `categories/low-hanging-fruits-1.html` → `categories/your-slug.html`,
   update the `<title>`, breadcrumb, `<h1>`, intro paragraph, and the final
   `<script>` block's `data-*.js` reference, array name, and `localStorage`
   page key (third argument to `renderVulnList`).
3. Add a nav link to the new page in **every** HTML file's `.nav-links` block
   (home, get-started, and all category pages).
4. Replace the matching "COMING SOON" card on `index.html`'s directory grid
   with a live `<a class="dir-card">` pointing at the new page, and update
   the `17` / `03` numbers in the hero stats if you want them to stay
   accurate.

## Progress tracking

The checkbox on each entry writes to `localStorage` under
`codex-progress::<page-key>` — per browser, per device, nothing is sent
anywhere. Clearing site data resets it. There's no backend by design, so this
stays a zero-maintenance static site indefinitely.

## A note on the theme

This went with an original "multiversal hacker" visual language — void
backgrounds, portal/rift energy, a color-coded severity spectrum — instead of
actual Marvel/DC character art or logos. Licensed character designs stay
copyrighted regardless of personal, non-commercial use, so nothing here
reproduces any studio's IP; the comic-book *feel* (motion, color, halftone
texture, bold display type) is built from scratch instead.

Each directory carries its own color "energy signature," set via a
`data-realm` attribute on `<body>` and consumed by CSS custom properties
(`--accent` / `--accent-2` / `--accent-3`) in `style.css`:

| Page | `data-realm` | Palette |
|---|---|---|
| Home | `cap` | blue / red / star-white — "First-Strike Protocol" |
| Part 1 | `hulk` | gamma green / violet — "Gamma Protocol" |
| Part 2 | `ironman` | hot red-orange / gold — "Repulsor Array" |
| Part 3 | `wakanda` | violet / silver — "Vibranium Vault" |
| Broken Access Control | `thor` | storm blue-white / asgardian gold — "Bifrost Protocol" |
| Security Misconfiguration | `loki` | mischief emerald / antique gold — "Variant Branch" |

**Severity badge colors are fixed and never change with the realm** — red
always means critical, gold always means medium, etc., regardless of which
directory you're on. Only the brand/decorative accents (hero glow, buttons,
card hover, section labels) shift per page. To re-theme or add a realm,
define a new `body[data-realm="..."]` block near the top of `style.css` with
its own `--accent`/`--accent-2`/`--accent-3` (plus the `-rgb` variants used
in `rgba()` calls) and set that value on the new page's `<body>` tag.

A ☀/🌙 toggle in the nav switches between the dark theme (default) and a
light theme, persisted in `localStorage` under `codex-theme` and applied via
`:root[data-theme="light"]` overrides in `style.css`. Code blocks stay dark
in both themes on purpose (a "terminal inside the document" look).

Fonts: **Saira Stencil One** for the hero headline and big stat numbers only
(the one deliberately bold moment), **Saira Condensed** for every other
heading, **Manrope** for body text, **JetBrains Mono** for code — all via
Google Fonts, loaded in `style.css`'s `@import`.

**Background art and card icons are procedural, not generated images.** Each
realm has a full-page animated background (`body::before`, driven by a
`--realm-pattern` custom property) built entirely from layered CSS
gradients — a gamma "burst" field for Hulk, concentric repulsor rings for
Iron Man, a triangulated mesh for Wakanda, a drifting starfield for Cap —
slowly panning and pulsing. Every vulnerability card also gets a small
category icon (shield/folder/terminal/gauge, hand-drawn as plain SVG
shapes in `app.js`'s `ICONS` object) and an animated "impact bar" next to
its severity badge. None of it is AI-generated artwork or licensed
character imagery on purpose — it's lighter to load, infinitely re-themeable
by editing a gradient, and keeps the whole project copyright-clean.

On top of that: nav links get a sliding underline, primary buttons get a
light-sweep on hover, the checkbox pops when you mark something tested, the
progress bar has a moving shimmer, "coming soon" cards shimmer to signal
they're inactive, the live filter dims non-matching entries instead of
snapping them away, section panels fade/rise in as you scroll past them
(`IntersectionObserver`, degrades to "just visible" with no JS), and the
homepage stat numbers count up from zero on load.

**The background is now a live `<canvas>` particle field**, not just a
static gradient (`initRealmCanvas` in `app.js`), with genuinely different
physics per realm rather than the same loop recolored:
- **Hulk** — motes drift upward with a small random walk each frame, like
  rising radiation, and respawn from the bottom when they exit the top.
- **Iron Man** — particles orbit two repulsor-like focal points on elliptical
  paths, with a soft pulsing glow at each center.
- **Wakanda** — particles drift freely and draw a thin connecting line to
  any neighbor within ~130px, so a live vibranium "circuit mesh" forms and
  reshapes as they move.
- **Cap** — a gentle starfield drift, plus a rare (~0.4%/frame) shooting
  star that streaks across and fades.
- **Thor** — ambient drift plus a rare (~0.6%/frame) jagged lightning bolt
  that strikes top-to-bottom and flashes out over a few frames.
- **Loki** — particles occasionally cast a faint "illusion" duplicate that
  drifts its own way and dissolves — a cheap, convincing stand-in for the
  character's whole shtick without drawing him.

Colors are read live from each page's `--accent-rgb` custom properties, so
re-theming a realm in `style.css` re-colors its particles automatically —
nothing is hardcoded twice. It skips entirely under
`prefers-reduced-motion`, pauses via the Page Visibility API when the tab
isn't active, and caps its particle count by viewport width (lighter on
mobile) so it stays cheap to run.

## Scope reminder

Every entry assumes authorized testing only — an active bug bounty program,
VDP, or your own infrastructure. Several entries (DoS, SPF/email spoofing)
are commonly excluded by individual program policies; check scope before you
test, not after.
