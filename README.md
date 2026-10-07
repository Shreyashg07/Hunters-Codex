<div align="center">

<img src="./assets/banner.png" alt="The Hunter's Codex" width="100%">

# ⚔️ The Hunter's Codex

### A Living Bug Bounty & Web Security Testing Checklist

**A personal, interactive security methodology for reconnaissance, vulnerability discovery, validation, and responsible disclosure.**

<br>

![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=flat-square&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=flat-square&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=flat-square&logo=javascript&logoColor=black)
![GitHub Pages](https://img.shields.io/badge/Hosted%20on-GitHub%20Pages-222222?style=flat-square&logo=githubpages&logoColor=white)
![No Backend](https://img.shields.io/badge/Backend-None-success?style=flat-square)
![No Build](https://img.shields.io/badge/Build%20Step-None-blue?style=flat-square)

</div>

---

## 🎯 About

**The Hunter's Codex** is a static, browser-based bug bounty checklist designed to keep web security testing methodology organized, searchable, and actionable.

It is intentionally lightweight:

- No backend
- No database
- No build step
- No JavaScript framework
- No package installation
- Works locally by opening `index.html`
- Deployable directly through GitHub Pages
- Progress is stored locally in the browser

The project is designed as a **living checklist** rather than a static document. Security checks can be added or expanded without rebuilding the entire application.

---

## ✨ Features

### 🔎 Security Methodology

Organize testing into practical security categories including:

- Low-hanging-fruit checks
- Broken Access Control
- CSRF
- IDOR / BOLA
- Security Misconfiguration
- Subdomain Takeover
- Reconnaissance and validation workflows
- Burp Suite methodology
- Decision-tree based testing

### 📋 Interactive Vulnerability Cards

Each vulnerability entry can contain:

- Description
- Impact
- Severity
- Steps to reproduce
- Decision trees
- Burp Suite walkthroughs
- Additional methodology and tools
- Reporting guidance

### 📈 Local Progress Tracking

Every checklist item can be marked as tested.

Progress is stored using browser `localStorage`:

```text
codex-progress::<page-key>
```

Nothing is sent to a server.

Clearing browser site data resets the progress.

### 🎨 Dynamic Security Themes

Each directory can have its own visual identity using CSS custom properties:

```css
--accent
--accent-2
--accent-3
--accent-rgb
```

Current realms include:

| Directory | Realm | Visual Theme |
|---|---|---|
| Home | `cap` | Blue / red / star-white |
| Part 1 | `hulk` | Gamma green / violet |
| Part 2 | `ironman` | Hot red-orange / gold |
| Part 3 | `wakanda` | Violet / silver |
| Broken Access Control | `thor` | Storm blue-white / gold |
| Security Misconfiguration | `loki` | Emerald / antique gold |

### ☀️ Dark / Light Mode

The navigation includes a theme toggle.

The selected theme is persisted in:

```text
codex-theme
```

Code blocks intentionally remain dark in both modes to preserve a terminal-style appearance.

### ⚡ Animated UI

The site includes lightweight procedural effects such as:

- Animated realm backgrounds
- Canvas particle fields
- Hover effects
- Sliding navigation underlines
- Button light sweeps
- Progress-bar shimmer
- Vulnerability-card reveal animations
- Interactive filters
- Scroll-based section reveals
- Homepage statistics count-up animations

Animations automatically respect:

```text
prefers-reduced-motion
```

The particle system also pauses when the page is not visible.

---

# 🗂️ Security Directory

The project currently organizes the checklist into several testing areas:

```text
Low-Hanging Fruits
├── Part 1
├── Part 2
└── Part 3

Broken Access Control
└── CSRF
└── IDOR / BOLA

Security Misconfiguration
└── Subdomain Takeover
```

The structure is intentionally modular so additional vulnerability directories can be added later.

---

# 🏗️ Project Structure

```text
hunters-codex/
│
├── index.html
├── get-started.html
│
├── categories/
│   ├── low-hanging-fruits-1.html
│   ├── low-hanging-fruits-2.html
│   ├── low-hanging-fruits-3.html
│   ├── broken-access-control.html
│   └── security-misconfiguration.html
│
└── assets/
    ├── css/
    │   └── style.css
    │
    └── js/
        ├── app.js
        ├── data-lhf1.js
        ├── data-lhf2.js
        ├── data-lhf3.js
        ├── data-access-control.js
        └── data-subdomain-takeover.js
```

### Core files

| File | Purpose |
|---|---|
| `index.html` | Animated homepage and directory navigation |
| `get-started.html` | Methodology, severity legend, and ground rules |
| `style.css` | Complete visual theme and responsive styling |
| `app.js` | Navigation, canvas effects, card rendering, filtering, progress, and reveals |
| `data-lhf1.js` | Low-Hanging Fruits — Part 1 |
| `data-lhf2.js` | Low-Hanging Fruits — Part 2 |
| `data-lhf3.js` | Low-Hanging Fruits — Part 3 |
| `data-access-control.js` | Broken Access Control content |
| `data-subdomain-takeover.js` | Security Misconfiguration content |

---

# 🚀 Quick Start

## Run Locally

No installation is required.

Simply open:

```text
index.html
```

in a modern browser.

Because the project is a static site, the local experience is designed to match the deployed GitHub Pages version.

---

# 🌐 Deploy to GitHub Pages

### 1. Create a repository

Create a new GitHub repository, for example:

```text
hunters-codex
```

Push the project files to the `main` branch while preserving the directory structure.

### 2. Enable GitHub Pages

Go to:

```text
Repository
→ Settings
→ Pages
→ Build and deployment
→ Source
→ Deploy from a branch
```

Select:

```text
Branch: main
Folder: / (root)
```

### 3. Open the site

Your site will be available at:

```text
https://<your-username>.github.io/hunters-codex/
```

GitHub Pages normally publishes the site shortly after deployment.

Because the project uses relative paths, it works both from:

```text
username.github.io/hunters-codex/
```

and from a custom domain root.

---

# ➕ Adding a New Vulnerability

Existing category pages use a data-driven architecture.

Open the appropriate:

```text
assets/js/data-*.js
```

file and add a new object following the existing structure:

```javascript
{
  id: "unique-kebab-case-id",
  title: "Human Readable Title",
  category: "Short Category Label",
  severity: "critical|high|medium|low|info",

  descriptionHTML: `...`,
  impactHTML: `...`,
  severityHTML: `...`,
  stepsHTML: `...`,

  treeHTML: `...`,
  burpHTML: `...`,
  extraHTML: `...`,

  reportYesHTML: `...`,
  reportNoHTML: `...`
}
```

Optional fields can be omitted when they are not required.

---

# 🧩 Adding a New Security Directory

To create an entirely new category:

### 1. Duplicate a data file

For example:

```text
assets/js/data-lhf1.js
```

to:

```text
assets/js/data-X.js
```

Rename the exported array and replace the entries.

### 2. Duplicate a category page

For example:

```text
categories/low-hanging-fruits-1.html
```

to:

```text
categories/your-category.html
```

Update:

- Page title
- Breadcrumb
- Heading
- Introduction
- Data-file reference
- Array name
- `localStorage` page key

### 3. Update navigation

Add the new category to the `.nav-links` section across the relevant HTML pages.

### 4. Update the homepage

Replace the corresponding `COMING SOON` card with a live directory card.

---

# 🧠 Data-Driven Architecture

Category pages are intentionally kept thin.

The HTML page loads the appropriate JavaScript data file and renders the vulnerability cards through:

```javascript
Codex.renderVulnList(
  'vuln-list',
  LHF1,
  'low-hanging-fruits-1'
);
```

This keeps:

```text
Structure → HTML
Content   → JavaScript data
Styling   → CSS
Behavior  → app.js
```

Adding a new vulnerability therefore does not require rewriting the category page.

---

# 🎨 Design System

The project uses a custom "multiversal hacker" visual language built without relying on licensed character artwork.

The design combines:

- Dark security-console aesthetics
- Bold display typography
- Realm-specific color systems
- Halftone-inspired textures
- Animated gradients
- Procedural particle effects
- Security dashboard elements
- Severity-based visual hierarchy

The project intentionally creates a comic-book-inspired atmosphere without reproducing copyrighted character designs or studio logos.

---

# 🔤 Typography

The visual system uses:

| Font | Usage |
|---|---|
| **Saira Stencil One** | Hero headlines and major statistics |
| **Saira Condensed** | Headings |
| **Manrope** | Body text |
| **JetBrains Mono** | Code and technical content |

Fonts are loaded through Google Fonts in the main stylesheet.

---

# 🌌 Procedural Background System

The backgrounds are generated through CSS and JavaScript rather than static artwork.

Each realm uses a different particle behavior.

### Hulk — Gamma Protocol

Particles drift upward with randomized movement, creating a rising radiation effect.

### Iron Man — Repulsor Array

Particles orbit multiple focal points on elliptical paths with pulsing centers.

### Wakanda — Vibranium Vault

Particles form a dynamic mesh by connecting nearby particles.

### Cap — First-Strike Protocol

Particles create a drifting starfield with occasional shooting stars.

### Thor — Bifrost Protocol

Ambient particles are combined with occasional lightning effects.

### Loki — Variant Branch

Particles can create subtle illusion duplicates that drift and fade independently.

The system uses the realm's CSS color variables, so changing the palette automatically recolors the particle system.

---

# ⚡ Performance

The project is designed to remain lightweight despite its animated interface.

Performance considerations include:

- No frontend framework
- No backend
- No build process
- Reduced particle count on smaller screens
- `prefers-reduced-motion` support
- Page Visibility API support
- CSS-based visual effects
- Procedural backgrounds
- Relative asset paths

When the browser tab is inactive, the particle animation pauses.

---

# 🔐 Responsible Testing

The Hunter's Codex is intended for:

- Authorized penetration testing
- Bug bounty programs
- Vulnerability Disclosure Programs
- Personal security research
- Owned infrastructure

Always verify the target's scope and rules **before testing**.

Some techniques may be explicitly excluded by individual programs, including certain:

- Denial-of-Service testing
- Email spoofing tests
- Automated scanning
- High-volume requests
- Third-party infrastructure testing

> **Scope first. Test second. Report responsibly.**

---

# 🛡️ Reporting Philosophy

A useful vulnerability report should clearly establish:

```text
What happened?
        ↓
Why does it matter?
        ↓
How can it be reproduced?
        ↓
What is the security impact?
        ↓
What evidence proves the issue?
        ↓
How can it be fixed?
```

The Codex is intended to help turn scattered testing ideas into a repeatable methodology.

---

# 🗺️ Roadmap

Potential future additions:

- [ ] Additional authentication checks
- [ ] SSRF methodology
- [ ] XSS testing directory
- [ ] API security directory
- [ ] JWT security checks
- [ ] OAuth testing methodology
- [ ] GraphQL security checks
- [ ] File upload testing
- [ ] Business logic testing
- [ ] Race-condition methodology
- [ ] Cloud security checks
- [ ] More Burp Suite workflows
- [ ] More decision trees
- [ ] Exportable testing reports

---

# ⚠️ Disclaimer

This project is an educational and security-research resource.

Use it only against systems for which you have explicit authorization to test.

The author is not responsible for unauthorized access, disruption, data loss, or misuse resulting from the techniques documented in this project.

---

# 📜 License

Choose a license appropriate for your repository before publishing.

For a personal open-source checklist, **MIT License** is a common option, but you should add the actual `LICENSE` file separately if you choose it.

---

<div align="center">

### ⚔️ Hunt Smart. Validate Carefully. Report Responsibly.

**The Hunter's Codex**

`Recon → Identify → Validate → Document → Report`

</div>
