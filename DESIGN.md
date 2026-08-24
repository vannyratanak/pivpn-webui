---
name: PiVPN Web UI
description: A self-hosted, dark-first admin console for PiVPN/OpenVPN — plain, functional, no decoration competing with the data.
colors:
  console-blue: "#4f8cff"
  console-blue-light: "#2f5fd6"
  deep-slate: "#0f1420"
  deep-slate-light: "#f1f4fa"
  slate-panel: "#161d2e"
  slate-panel-light: "#ffffff"
  slate-panel-raised: "#1c2438"
  slate-panel-raised-light: "#eef1f7"
  slate-border: "#5a6a94"
  slate-border-light: "#8290ab"
  frost-text: "#e6e9f0"
  frost-text-light: "#0f172a"
  slate-muted: "#8a93a8"
  slate-muted-light: "#475569"
  mint-ok: "#3ecf8e"
  mint-ok-light: "#15803d"
  amber-warn: "#f5a623"
  amber-warn-light: "#b45309"
  coral-danger: "#f0556c"
  coral-danger-light: "#dc2626"
  pure-danger: "#ed0000"
  pure-danger-light: "#dc2626"
typography:
  display:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "22px"
    fontWeight: 700
    lineHeight: 1.3
    letterSpacing: "normal"
  title:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "16px"
    fontWeight: 700
    lineHeight: 1.3
    letterSpacing: "normal"
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "15px"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
  label:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
  caption:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
  control:
    fontFamily: "-apple-system, BlinkMacSystemFont, \"Segoe UI\", sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
  mono:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: 1.5
    letterSpacing: "normal"
rounded:
  sm: "4px"
  md: "6px"
  lg: "8px"
  xl: "10px"
  pill: "999px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "14px"
  lg: "20px"
components:
  button-primary:
    backgroundColor: "{colors.console-blue}"
    textColor: "#ffffff"
    rounded: "{rounded.md}"
    padding: "0 14px"
    height: "34px"
  button-secondary:
    backgroundColor: "{colors.slate-panel-raised}"
    textColor: "{colors.frost-text}"
    rounded: "{rounded.md}"
    padding: "0 14px"
    height: "34px"
  button-danger:
    backgroundColor: "{colors.pure-danger}"
    textColor: "#ffffff"
    rounded: "{rounded.md}"
    padding: "0 14px"
    height: "34px"
  input-field:
    backgroundColor: "{colors.slate-panel-raised}"
    textColor: "{colors.frost-text}"
    rounded: "{rounded.lg}"
    padding: "10px 12px"
  card:
    backgroundColor: "{colors.slate-panel}"
    textColor: "{colors.frost-text}"
    rounded: "{rounded.xl}"
    padding: "20px"
  badge:
    backgroundColor: "{colors.mint-ok}"
    textColor: "{colors.mint-ok}"
    rounded: "{rounded.pill}"
    padding: "2px 8px"
---

# Design System: PiVPN Web UI

## Overview

**Creative North Star: "The Ops Console"**

This is a dark-first admin console for a job most people only do over SSH: managing an OpenVPN server's clients, firewall rules, and logs. The interface assumes an operator who already knows what an iptables rule or a CIDR block is — nothing here explains itself with icons or friendly copy, because the friendliness would be wasted on this audience and the space would be better spent on the actual data. Density and legibility win over polish; a table of 30 firewall rules with sortable columns matters more than a hero section ever would.

There is no separate visual brand layered on top of the functionality — the "brand" is the discipline of the system itself: one accent color reserved for actionable/selected things, three status colors reserved for real state (success/warning/danger), everything else rendered in a narrow band of near-black slate and muted gray-blue text. Nothing competes for attention that isn't actually meaningful.

Confirmed rejection: no illustration, no decorative iconography beyond small functional glyphs (chevrons, a drag handle, theme sun/moon), no gradients, no marketing-style hero treatment anywhere in the product.

**Key Characteristics:**
- Dark by default, with a fully-parallel light theme (same structure, inverted lightness) — never a half-implemented afterthought
- One accent color, three semantic status colors, everything else neutral slate
- Flat surfaces at rest; shadow only appears on things that are genuinely floating (open dropdowns, modals) or interactive (button hover)
- Dense, table-first layouts — real iptables/IP/port values shown verbatim, never paraphrased

## Colors

A narrow, disciplined palette: one accent color that means "actionable," three status colors that mean something specific (success/warning/danger), and a slate-navy neutral scale that does all the actual surface and text work.

### Primary
- **Console Blue** (`#4f8cff`, `#2f5fd6` in light mode): The one accent color in the entire system — focus rings, links, primary buttons, active nav underline, the "Saved"/selected state on the custom dropdown. Used sparingly and consistently; if something is blue, it's because you can act on it.

### Neutral
- **Deep Slate** (`#0f1420`, `#f1f4fa` in light mode): The page background — the deepest surface in the stack.
- **Slate Panel** (`#161d2e`, `#ffffff` in light mode): Card, table-header, and topbar background — one step up from the page background.
- **Slate Panel Raised** (`#1c2438`, `#eef1f7` in light mode): Input fields, custom-select triggers, and the "unpressed" state of secondary buttons — one more step up, for things embedded inside a panel.
- **Frost Text** (`#e6e9f0`, `#0f172a` in light mode): Primary text color.
- **Slate Muted** (`#8a93a8`, `#475569` in light mode): Secondary text — hints, table headers, nav links at rest, timestamps. Both values are deliberately contrast-checked (4.5:1+ against both `--bg` and `--panel`) rather than picked by eye.
- **Slate Border** (`#5a6a94`, `#8290ab` in light mode): The one border/divider color used everywhere — card edges, input outlines, table row dividers. Also deliberately contrast-checked (3:1+ against `--panel`, the WCAG 1.4.11 non-text contrast minimum for UI component boundaries).

### Status colors (not decorative — each one means a specific state)
- **Mint OK** (`#3ecf8e`, `#15803d` in light mode): Success — "connected" badges, the Enable/Renew-adjacent affirmative button, "Saved" state.
- **Amber Warn** (`#f5a623`, `#b45309` in light mode): Caution, not yet danger — the Block/Disable button family.
- **Coral Danger** (`#f0556c`, `#dc2626` in light mode): The `--danger` token itself — used for text/badges/borders needing a danger tone at low-to-medium contrast needs.
- **Pure Danger** (`#ed0000`, fixed, not theme-derived): The actual Delete/Remove button background specifically — deliberately a different, more saturated red than the `--danger` token, because white button text on `--danger`'s dark-mode value only clears 3.38:1 (fails WCAG 4.5:1). `#ed0000` was chosen as the closest match to the originally-requested red that still clears 4.5:1 with white text.

### Named Rules
**The One Accent Rule.** Console Blue is the only color in the system that means "you can act on this." It never appears as pure decoration — every blue pixel is a link, a focus ring, a primary action, or a selected state.

## Typography

**Body/UI Font:** `-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif` (the OS-native system font stack, not a custom webfont)
**Mono Font:** `ui-monospace, SFMono-Regular, Menlo, Consolas, monospace` (log/journal views and inline `<code>` only)

**Character:** Deliberately un-opinionated — the system font stack renders as whatever the operator's own OS looks like, which reads as "native tool," not "web app pretending to be native." Monospace is reserved for places where column alignment or literal character-for-character accuracy matters (logs, `<code>` snippets).

### Hierarchy
- **Display** (700, 22px, 1.3 line-height): Page titles only (`<h1>` — "Firewall Rules," "VPN Clients"). One per page.
- **Title** (700, 16px, 1.3 line-height): Card/section headings (`<h2>` — "Active rules," "Add client").
- **Body** (400, 15px, 1.5 line-height): Default running text and most UI copy.
- **Control** (400, 14px, 1.5 line-height): The actual text inside every interactive control — inputs, selects, buttons, the custom-dropdown trigger. Distinct from Body: this is what you type into or click, not what you read.
- **Caption** (400, 13px, 1.5 line-height, usually `color: var(--muted)`): Table cell content, form field labels (the word above an input, not its value), and pagination text — structural secondary text that's still part of the content, not a pure annotation.
- **Label** (400, 12px, 1.5 line-height, `color: var(--muted)`): `.hint` text specifically — a purely annotational aside ("optional — leave blank for a passwordless cert"), one step quieter than Caption. Always Slate Muted, never full-contrast text.

### Named Rules
**The No-Webfont Rule.** Typography never loads a custom font file. The system stack is the point — this is a tool, not a brand surface, and a native-feeling font reinforces that.

## Layout

Single-column page structure: a sticky top navigation bar, then a stack of `.card` sections (max content width capped, centered), each card holding one coherent unit of work (a form, a table, a settings block). Cards stack vertically with 20px margins between them; nothing sits side-by-side except within a card's own header row (title + action buttons, space-between).

Forms use a 4-column CSS grid (`.inline-form`, `repeat(4, 1fr)`, 14px gap) that collapses to 2 columns at 900px and 1 column at 520px — never truncating or hiding a field, only re-stacking it. Tables use fixed-width columns on desktop (so layout doesn't jitter) and rely on horizontal scroll (with a deliberately-visible thin scrollbar, not a hidden one) rather than shrinking columns below a usable width on narrow viewports.

Interactive controls (buttons, the custom dropdown trigger) are a **consistent 34px tall** everywhere at every viewport width — this was a real, recently-fixed inconsistency (a `<button>`-based custom dropdown and its neighboring `.btn-sm` pagination controls drifted to different heights through several browser quirks before being pinned to match). Text inputs are a separate, taller 43px, matching each other but intentionally not matching buttons — inputs and buttons are visually distinct control families, not meant to look identical.

### Named Rules
**The Never-Shrink-Below-Usable Rule.** A table or form never gets visually cramped to fit a narrow screen — it either re-flows to fewer columns or gains a scrollbar, but a value (an IP, a rule, a client name) is never truncated or hidden to save space.

## Elevation & Depth

Flat by default — cards, tables, and inputs use only a single 1px border (`--border`) at rest, no `box-shadow`. Depth is a signal, not a decoration: the only elements that ever cast a shadow are things that are genuinely floating above the page (open custom-dropdown menus, `<dialog>` modals) or reacting to interaction (a button's hover state gets a slightly heavier shadow than its resting state, which has none at all beyond a subtle 1px-equivalent ambient shadow).

### Shadow Vocabulary
- **Resting button** (`box-shadow: 0 1px 2px rgba(0,0,0,0.15)`): The one shadow present even at rest — just enough to lift a filled button off the flat page.
- **Hover button** (`box-shadow: 0 2px 5px rgba(0,0,0,0.2)`): A visibly heavier lift on hover, paired with a brightness increase.
- **Open dropdown menu** (`box-shadow: 0 8px 24px rgba(0,0,0,0.25)`): The heaviest shadow in the system — reserved for the one element that's genuinely floating above everything else.
- **Modal backdrop** (`::backdrop { background: rgba(0,0,0,0.6) }`): Not a shadow on the modal itself but the same "floating above the page" signal applied to everything *behind* it — the page dims rather than the dialog casting a shadow onto it.

### Named Rules
**The Flat-At-Rest Rule.** Nothing gets a shadow just for existing. A card, a table, an input — all flat, bordered, done. Shadow is earned only by floating above the page or reacting to a hover/press.

## Shapes

A tight, deliberate radius scale, larger for bigger/more prominent surfaces: `4px` (small inline elements like the drag-handle and inline `<code>`), `6px` (buttons), `8px` (inputs and the custom-select trigger), `10px` (cards and modals — the largest container surfaces), and `999px` (fully-pill badges, the one place the scale breaks its own logic on purpose, since a status badge is meant to read as a distinct "chip" shape, not a rectangle).

Borders are always the single `--border` slate-blue token, always 1px, never a second border color or a double-border effect anywhere in the system.

## Components

### Buttons
- **Shape:** 6px radius, 34px height, `0 14px` padding — consistent across every button in the system, including the custom-select dropdown trigger (34px) once it was fixed to stop drifting to native-`<button>`-quirk heights.
- **Primary** (`.btn`, default): Console Blue background, white text, the resting/hover shadow pair above.
- **Secondary** (`.btn-secondary`): Slate Panel Raised background, Frost Text color, `--border` outline instead of a filled color — used for routine/neutral actions (e.g. Renew) that shouldn't visually compete with the four semantic-colored buttons (primary/ok/warn/danger).
- **Ok / Warn / Danger:** Filled with Mint OK / Amber Warn / Pure Danger respectively, each with a specifically contrast-checked text color (not always pure white — Warn and Ok both use a near-black text color, since white fails contrast against their brighter fills).
- **Compact variant** (`.btn-sm`, table row actions): 26px tall on desktop to fit several actions in one dense row; grows back to a 44px WCAG touch-target minimum below 600px viewport width, since the density trade-off that justifies 26px on desktop no longer applies on mobile.
- **Focus:** every button, including third-party-feeling ones like a modal's close `×`, gets the same `2px solid` Console Blue outline with `2px` offset on `:focus-visible` — no unstyled default outlines anywhere.

### Cards / Containers
- **Corner Style:** 10px radius.
- **Background:** Slate Panel.
- **Shadow Strategy:** none (see Elevation & Depth) — a single `--border` outline is the only edge treatment.
- **Internal Padding:** 20px, uniform on all sides.

### Inputs / Fields
- **Style:** Slate Panel Raised background, `--border` outline, 8px radius, 43px tall (10px vertical + 12px horizontal padding, 21px line-height, 1px border).
- **Focus:** border color shifts to Console Blue; no glow or shadow added, just the color shift plus the standard focus-visible outline where applicable.
- **The custom dropdown** (`select-enhance.js` + `.custom-select-trigger`): every `<select>` in the system is replaced with a synthetic `<button>`-based trigger + a fully custom-rendered option menu, so the open dropdown list looks identical across every browser (a native `<select>` popup is OS-drawn and unstylable). Matches the plain text input's 43px height and left-aligned text everywhere except the pagination "Show N" and Firewall "Filter by client" contexts, which are explicitly the shorter 34px button height instead, since those specific instances sit directly beside regular buttons rather than form fields.

### Navigation
- **Style:** A sticky top bar (`Slate Panel` background, `--border` bottom edge) holding the brand mark, a flat inline nav (no pills/boxes around links), and the theme toggle + logout on the right.
- **Default/Hover/Active:** Nav links are Slate Muted at rest, shift to Frost Text + a Console Blue underline on hover, and stay on that same underlined treatment (plus `aria-current="page"`) when active.
- **Mobile:** the nav wraps onto a second line below the brand/utility row rather than collapsing into a hamburger menu — there are only 4 destinations, so a full disclosure menu would add a tap for no real space savings.

### Badges
- **Style:** Fully pill-shaped (999px radius), small (11px uppercase text, `0.03em` letter-spacing), background is always a low-opacity (15–18%) tint of the underlying status color with the same color used at full opacity for the text — never a solid fill.
- **State:** Connected/success uses Mint OK; inactive/neutral uses Slate Muted. No warning or danger badge variant exists yet (both live states covered are binary: connected or not).

## Do's and Don'ts

### Do:
- **Do** keep every button — including any future custom control — at the shared 34px height and 6px radius, so the whole system reads as one consistent control family.
- **Do** reserve Console Blue for things that are actually actionable (links, primary buttons, focus, selection) — never as pure decoration.
- **Do** contrast-check any new color pairing against both `--bg` and `--panel` before shipping it — this system has already found and fixed two WCAG 1.4.3/1.4.11 failures by doing exactly that (see the inline comments in `style.css`).
- **Do** show real values (IPs, ports, iptables flags, CIDR blocks) verbatim rather than paraphrasing them into friendlier-sounding copy — the audience already speaks this language.

### Don't:
- **Don't** add a shadow to a surface just because it's a container — flat + a 1px border is the resting state for everything; shadow is earned by floating (dropdowns, modals) or reacting (button hover), not by existing.
- **Don't** introduce a second border color, a gradient, or decorative iconography — the palette is deliberately narrow, and that narrowness is the actual visual identity, not a placeholder waiting to be replaced.
- **Don't** let a `<button>`-based custom control (like the dropdown trigger) inherit native browser button styling unchecked — `appearance`, `display`, and explicit `height`/`min-height` all need resetting independently, or native button quirks (centered text, wrong auto-height) leak through. See the inline comments around `.custom-select-trigger` in `style.css`.
- **Don't** shrink a table or form to fit a small screen by making values harder to read — reflow to fewer columns or add a scrollbar instead.
