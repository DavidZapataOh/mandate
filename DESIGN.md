---
name: Mandate Console
description: A live pixel branch where every agent request crosses one teller window carrying the Mandate seal, or dies there.
colors:
  ink: "#0B0D10"
  bone: "#F6F4EE"
  verify: "#1FD598"
  alert: "#FF5C5C"
  muted: "#8A8F98"
  booth-face: "#EFF2E7"
  world-0: "#070E10"
  world-1: "#081514"
  world-2: "#0E1D1B"
  world-3: "#142D26"
  world-4: "#062317"
  world-5: "#1E4B38"
  world-6: "#2A6C4A"
  world-7: "#3C7959"
  world-8: "#55A673"
  world-9: "#7FD493"
  world-10: "#CCE3C7"
  world-11: "#EFF2E7"
  world-12: "#62775A"
  world-13: "#31372F"
  world-14: "#5F5E2B"
  world-15: "#989C4E"
typography:
  wordmark:
    fontFamily: "Mandate lockup (SVG)"
    fontSize: "48px"
  counters:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "20px"
    fontWeight: 400
    lineHeight: 1
    fontFeature: "tnum"
  ledger-row:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "22px"
    fontWeight: 400
    lineHeight: "31px"
    fontFeature: "tnum"
  world-tag:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "max(14px, calc(var(--scale) * 19px / 3))"
    fontWeight: 400
    lineHeight: 1.05
    letterSpacing: "-0.04em"
  alert:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "max(14px, calc(var(--scale) * 16px / 3))"
    fontWeight: 700
    lineHeight: 1
    letterSpacing: "-0.04em"
  booth-sign:
    fontFamily: "Press Start 2P, JetBrains Mono, monospace"
    fontSize: "max(14px, calc(var(--scale) * 4.8px))"
    fontWeight: 400
    lineHeight: 1
    letterSpacing: "0.08em"
  label:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.2
    letterSpacing: "0.02em"
  headline:
    fontFamily: "Inter, system-ui, sans-serif"
    fontSize: "22px"
    fontWeight: 700
    lineHeight: 1.2
  body-mono:
    fontFamily: "JetBrains Mono, ui-monospace, monospace"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.5
rounded:
  none: "0px"
  strip: "4px"
spacing:
  hair: "4px"
  sm: "8px"
  md: "12px"
  lg: "24px"
components:
  world-tag:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.bone}"
    typography: "{typography.world-tag}"
    rounded: "{rounded.none}"
    padding: "4px 8px"
  alert-bar:
    backgroundColor: "{colors.alert}"
    textColor: "{colors.ink}"
    typography: "{typography.alert}"
    rounded: "{rounded.none}"
    height: "calc(10px * var(--scale))"
  seal-face:
    backgroundColor: "{colors.booth-face}"
    textColor: "{colors.ink}"
    width: "calc(22px * var(--scale))"
    height: "calc(18px * var(--scale))"
  ledger-row:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.bone}"
    typography: "{typography.ledger-row}"
    height: "31px"
  mode-button:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.muted}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "4px 8px"
  mode-button-pressed:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.bone}"
  mode-button-active:
    backgroundColor: "{colors.bone}"
    textColor: "{colors.ink}"
  origin-badge:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.bone}"
    typography: "{typography.label}"
    rounded: "{rounded.none}"
    padding: "0 6px"
  forensic-drawer:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.bone}"
    width: "min(560px, 100%)"
    padding: "24px"
---

# Design System: Mandate Console

## Overview

**Creative North Star: "The Teller Window"**

The console is one small pixel world seen through a dark frame. Meta's agents work in an office on the left, the bank branch sits on the right, and between them stands a teller booth with the Mandate seal on its face. Every request walks to that window. A verified request joins the seal's halves with a green seam. An attack is refused: the halves shake apart, a red bar drops under the booth, and the intruder is thrown back. Everything around the world is dark security: Ink ground, Bone monospace labels, one-pixel hairlines, and a ledger of real events below.

The pixel world carries the warmth and the motion. The chrome stays quiet so the verdict at the booth is always the loudest thing on screen. Text is never painted into the world: tags, bubbles, the alert, the sign and every ledger cell are live DOM text set over the canvas, so they stay sharp, selectable and spoken. The brand commitments behind the palette and type (Ink and Bone, Verify reserved for verified states, Inter with JetBrains Mono, "dark security + pixel soul") are stated in `PRODUCT.md`. The surface's direction contract is `.impeccable/surfaces/console-index-html.md`.

**Key Characteristics:**
- An integer-scaled 444×164 pixel world at the centre of the first viewport, the booth always centred.
- A 16-colour duotone-green world palette, separate from the UI palette.
- Green means verified and red means refused, and nothing else uses either.
- Square Ink tags with Bone monospace text, and no rounded bubbles.
- One authored motion moment, the seal's verdict. The world drifts on its own; the proof surfaces never move.

## Colors

The UI is two neutrals and two signals. The world below it is a separate, closed duotone-green palette.

### Primary
- **Verify Green** (`verify`): the only success colour. It appears on the joined seal's seam, the VERIFIED word in a ledger row, the verified glyph and the verified count. Nothing decorative is ever green.

### Secondary
- **Refusal Red** (`alert`): the only failure colour. It appears on the alert bar under the booth, the refused seal's seam, a DENIED or NOT BLOCKED verdict and a struck hash. Text on it is Ink (6.4:1), because Bone on this red is 2.7:1.

### Neutral
- **Ink** (`ink`): the ground of the page, every tag, the drawer and the seal's halves.
- **Bone** (`bone`): primary text, the pressed button's rule, focus rings, selection and the 14% hairline (`rgb(246 244 238 / 0.14)`).
- **Muted Steel** (`muted`): secondary text. Used for row times, unstruck hashes, unpressed mode buttons, held and noted verdicts, separators and the scrollbar thumb. It is 6:1 on Ink.
- **Booth Face** (`booth-face`): sampled from the booth plate, so the seal reads as painted on the booth rather than placed over it.

### World palette
- **World 0–15** (`world-0` … `world-15`): the only colours a plate or frame may contain. Every generated raster is snapped to them by block majority before it ships. They are near-black greens through pale mint, two olive-golds for the bank desk, and a warm off-white that the booth face shares.

### Named Rules
**The Green Means Verified Rule.** Verify appears only where a gate decision verified something. A denied count stays Bone.

**The Two Palettes Rule.** UI colours never enter the world, and world colours never style the UI. The one bridge is the booth face, which the seal borrows from the plate.

## Typography

**Display Font:** none. The wordmark is the brand's white horizontal SVG lockup, shipped with the console as `mandate-horizontal-white.svg`.
**Body Font:** Inter (with system-ui), for drawer headings.
**Label/Mono Font:** JetBrains Mono (with ui-monospace), for every label, row, tag and number.
**World Signage:** Press Start 2P, loaded lazily and used only for the booth sign.

**Character:** a technical mono voice that reads like a ledger, set against one piece of pixel signage that belongs to the world. All three faces are self-hosted from pinned `@fontsource` packages, latin subset, weights 400 and 700.

### Hierarchy
- **Counters** (400, 20px, line-height 1, tabular numerals): `verified · denied · p50` in the top bar. 16px on phones.
- **Ledger row** (400, 22px, 31px pitch, tabular numerals): `time · actor · sentence · hash · verdict` plus a glyph. 16px with a 24px line on phones.
- **World tag** (400, `max(14px, scale × 19px / 3)`, −0.04em): names over figures and attacker bubbles. It follows the stage's integer scale and is 19px at 3×.
- **Alert** (700, `max(14px, scale × 16px / 3)`, −0.04em): the refusal sentence under the booth. 16px at 3×, never under 14px (a 2× laptop and phones).
- **Booth sign** (Press Start 2P 400, `max(14px, scale × 4.8px)`, +0.08em): `TELLER`.
- **Label** (400, 14px, +0.02em): stream state, GAME / FORENSIC, the TEMPLATE / MODEL origin badge.
- **Headline** (Inter 700, 22px, 1.2): the forensic drawer's title.
- **Body mono** (400, 14px, 1.5): forensic records, wrapped anywhere.

### Named Rules
**The Live Text Rule.** No word is ever drawn into the pixels. Every word is DOM text over the canvas, so a screen reader, a selection and a zoom all reach it.

**The Tracking Floor Rule.** Mono is never tracked tighter than −0.04em.

## Layout

The page is a single column of three bands at the stage's own width: a top bar at least 64px tall, the stage, and the ledger strip filling the rest of the height. The column is centred.

**The stage is always `fitStage`.** The native world is 444×164 pixels. The CSS scale is `max(2, min(floor(floor(viewH × 0.66) / 164), ceil(viewW / 444)))`, which is always an integer. The visible width is `min(444 × scale, viewW)`. When the world is wider than the screen, it is cropped evenly on both sides so the booth stays centred. The resulting scales are 3× at 1280–1440 wide (1332×492), 4× at 1600×1000 (1776×656, cropped to 1600), and 2× on a 390px phone (888×328, cropped to 390). The scale is measured from the document width, clamped by the visual viewport and the screen, so an overflowing element can never widen a phone's layout viewport into a desktop stage.

In-world elements are placed in native pixels multiplied by `--scale` and offset by `--crop-x`:
- booth (181, 38, 82×107)
- seal on the booth face (30, 27, 22×18 inside the booth)
- alert bar (centred on x 222.5, y 151, at least 115×10)

Bubbles and the fixed tags keep 8px inside the stage, and the top bar keeps 12px from the viewport edges when the stage is cropped. A walker's bubble straddles the figure and slides to stay whole when the stage is cropped. A walker's bubble ends at least 4px above the alert bar, and the holder's bubble at least 4px above the `TELLER` sign; a second line grows them upward.

**Below 720px:**
- the top bar wraps the counters onto their own line under the wordmark, at 16px
- the wordmark drops to 40px
- ledger rows become two lines at 16px: time, hash and verdict on the first; actor and sentence on the second, with the sentence ellipsized
- the origin badge is hidden visually and kept in the row's spoken name

Spacing steps are 4, 8, 12 and 24px. The ledger strip is inset 10px from the page edge on narrow screens and 12px past the stage on wide ones.

### Named Rules
**The Integer Pixel Rule.** The world is only ever drawn at a whole-number scale, with `image-rendering: pixelated`, `imageSmoothingEnabled = false` and every draw at a whole native pixel. Never stretch the stage to fill a width; crop it around the booth.

## Elevation & Depth

The page is flat. Depth lives inside the pixel world, in the plates' own perspective and shading. The UI uses no drop shadows. Stacking is by order alone: world canvas, overlay of tags and bubbles, booth and seal, alert, and the forensic drawer fixed over everything. The ledger's oldest visible row fades across the strip's open top edge through a 31px mask. That is the only gradient, and it marks history running out of view, not decoration. Hover on a row is a 1px inset Bone hairline (`box-shadow: inset 0 0 0 1px`), so the row pitch never changes.

### Named Rules
**The Flat Chrome Rule.** No shadows, glass or glows on UI. If something needs to stand forward, it gets Ink behind it and a Bone hairline around it.

## Shapes

Corners are square: tags, bubbles, buttons, badges, the alert bar and the drawer are all 0px. The one rounded shape is the ledger strip, with 4px corners at the bottom only. Its top edge is open, so its floor rule reads as the base of the list. Rules are 1px Bone at 14% opacity. The seal is the brand's Reunion mark: two stepped halves of an Ink square on the booth face. At rest the halves sit 8 units apart in the mark's 256 grid. A refusal opens them to 16 units and shakes them ±6 units. A verification closes them over 133ms. The mark is framed to its refused extent (16 to 240), so the halves fill the face's height without clipping.

## Components

### Top bar
- **Wordmark:** the white horizontal lockup, 48px tall, pulled 6px left so the mark meets the stage edge.
- **Stream state** (`LIVE`, `REPLAY`…): a label in an Ink box with a Bone hairline.
- **Mode toggle:** GAME / FORENSIC as square label buttons. Unpressed buttons are Muted. Pressed buttons are Bone with a Bone rule. On press, the fill turns Bone with Ink text.
- **Counters:** mono, tabular. The verified number is Verify Green; the denied number and p50 are Bone.

### World tags and bubbles
- **Tag:** an Ink rectangle, 4px × 8px padding, Bone mono at the world type size. Fixed tags name the figures: Muse Spark, Muse Code, and the courier.
- **Bubble:** a button made of a tag (who: `template attack`, `open-weights attacker`, an agent) and a sentence (what it tried). The sentence wraps to two lines before it is cut, one line on phones. Hover draws a Bone hairline. On press, the fill turns Bone with Ink text. A click opens the forensic record. A bubble lives for 3 seconds.

### Booth and seal (signature)
- **Booth:** a pixel plate centred in the world, with the `TELLER` sign in Press Start 2P.
- **Seal states**, each with a text and shape counterpart:
  - `wait`: halves apart, no seam.
  - `verify`: halves joined, Verify seam, VERIFIED in the ledger.
  - `deny`: halves pushed apart and shaking, Alert seam, red alert bar, DENIED in the ledger.
  - `breach` (a defence that did not hold): the seal never verifies, the bar reads `NOT BLOCKED`, and the row is never struck.
- **Engines:** the seal runs as a Rive state machine (`seal`: `verify`, `deny`, `wait`). An identical Canvas 2D seal draws from first paint and stays if Rive cannot load. The booth mirrors the engine's state into `data-seal`.

### Alert bar
- **Style:** Refusal Red, Ink bold mono, square, at least 10 native pixels tall, centred directly under the booth.
- **Copy:** `denied · <attack> · <latency or layer>`.
- **Behaviour:** its box is already placed, and its ink snaps in (see Motion). Seal and bar belong to the visitor at the window: the next visitor to reach the booth resets both, so a red bar never sits under a green seal or under another request. A verdict decided in place (a Muse Code tool call, the holder's tap) waits until the walker at the window has left.

### Ledger row
- **Style:** a full-width button, mono 22px on a 31px pitch, newest on top, at most 200 rows drawn.
- **Cells:**
  - time (Muted, UTC `HH:MM:SS` from the event, `--:--:--` when nothing reached the gate)
  - actor (Bone)
  - sentence (Bone, ellipsized)
  - hash (Muted, struck in Alert when refused)
  - verdict word (Verify, Alert or Muted)
  - a 22px seal glyph from the inline symbol set
- **Separators:** Muted ` · `, inline-block so a strike never runs through them.
- **States:** hover is an inset hairline, focus is a 2px Bone ring offset 2px, and press is a 6% Bone wash.

### Forensic drawer
- **Style:** fixed to the right, `min(560px, 100%)` wide, Ink, with a Bone hairline on its left edge.
- **Content:** an Inter 700 title, Muted mono section heads, and wrapped mono records.
- **Buttons:** square label buttons with the same hover and press as the mode toggle.

### Motion
- **The verdict moment** (the one authored animation): the alert bar and every new bubble enter from opacity 0 to 1 over 120ms on `cubic-bezier(0.16, 1, 0.3, 1)`. That is fast in and a dead stop, with no overshoot and no movement of the box. The seal's verify snap (133ms) and deny shake (80ms per step) belong to the same moment.
- **The world's own drift:** walkers move at 96 native px/s with 120ms walk frames. Ambient frames cycle at 140–400ms. The vault opens over 1.5s.
- **Never animated:** the ledger, the counters and the top bar. They are proof surfaces.
- **Reduced motion:** walks and frame cycles stop and every verdict still lands at once. Transitions are removed.

## Command

`console/command.html` is the executive posture view, a control register for agent actions. It lives in the console's settled world without the pixel scene: Ink ground, Bone text, Muted secondary, hairline rules, JetBrains Mono for every number, hash and seq. Its direction contract is `.impeccable/surfaces/console-command-html.md`. Every value on it is computed from the console's retained lines and this process's registry and policies, and every metric opens down to those lines.

### Layout
- **Top bar:** the wordmark (48–50px), the view name in Muted uppercase 17px Inter 700 with +0.1em tracking, and Export Markdown and Export JSON at the right. The bar closes on a 3px Muted rule, the only heavier rule on the page.
- **Provenance strip:** one Bone mono line on `#16181C` (one step off Ink) naming the window, where it starts and the registry it rests on. An empty registry reads `registry empty`, never a root over 0 entries. Stream state and the link back to the live console sit at its right.
- **Metric band:** eight equal cells divided by hairlines, then a hairline under the band.
- **Control register:** the framework table, grouped by framework.
- **Compact tables:** attacks by kind and denials by layer side by side, split by a vertical hairline.
- **Drill list:** under the tables, opened on demand.

The page gutter is `clamp(16px, 2.92vw, 48px)`. Columns are fluid from 1280 to 1600. A 1100–1380px step shrinks the compact tables' type so both stay whole beside each other.

### Metric cell
- **Label:** Inter 700 15px on a 19px line, balanced.
- **Value:** JetBrains Mono 700 at `clamp(36px, 3.34vw, 56px)`, tabular.
- **Shares and gate time:**
  - Shares (consent, attribution) use `clamp(20px, 1.7vw, 28px)` and render as two unbreakable spans, the count then `· share`, so a line never ends on the dot.
  - Gate time sets its two percentiles on one line at `clamp(11px, 0.85vw, 14px)`, with the Muted sample count under them.
  - A value that says the window has none (`none in this window`) drops to a 15px Bone 82% sentence.
- **Colour:** the verified value is always Verify. Attacks not blocked and Moved by attacks take Alert only when they are not zero (`data-zero="false"`). Every other value is Bone.
- **Below the value:** the Definition disclosure, and a `Show the n lines` drill button in Muted 12px underlined mono.

### Definition disclosure
A `summary` reading Definition, followed by an authored 14px info mark (ring, dot and stem, a data-URI mask filled with `currentcolor`). Opening it lays the exact definition over the page in a 320px Ink box with a 40% Bone hairline, so the band never shifts. The last three cells open leftward. The attacks and layers tables carry the same disclosure beside their headings.

### Control register
- **Heading:** an uppercase Inter 700 18px heading, with `17 provisions` (singular for one) in Muted 12px mono under it.
- **Disclaimer and applicability:** right-aligned in Muted 13px. The applicability line sits above the table it calls "below".
- **Header band:** `#5C5E62`, with Bone uppercase Inter 700 12.5px labels (5.1:1).
- **Rows:** `#16181C` separated by 2px Ink.
  - The framework name is in Inter 700 15px, said once per group; repeats are transparent but still spoken.
  - The rule between groups is 40% Bone.
  - Evidence is in mono 700.
  - Source is a mono link.
- **Size:** at desktop the register is a 275px scroll box with a sticky header. Its foot fades over 48px until it is scrolled to its end (`data-at-end`).
- **≤720px:** each provision stacks as a block. Every value carries its column name above it from `data-label`, in Muted 10.5px uppercase mono, with no nested scroll.

### Compact tables
- **Rows and header:** 22px rows on `#16181C` with 2px Ink gaps. The header is Muted 10.5px uppercase mono.
- **Text:** the kind or layer name is Inter 700 15px; numbers are mono and tabular, right-aligned.
- **Attacks total row:** below a 40% Bone rule, it counts only kinds attempted in the window, so an untried kind is never called blocked (`all 7 kinds blocked`, `all 3 attempted kinds blocked`, `3 of 4 attempted kinds blocked`, `no attacks attempted`).
- **An attack kind that got through:**
  - Its Not blocked and Moved cells turn Alert.
  - Stopped at reads `not stopped` in Alert 700.
  - The total names how many kinds held, in Alert.
- **≤720px:** the tables scroll sideways inside their section. The name column is sticky (`left: 0`, 104–120px, wrapping), on `--raised` in the body and on Ink in the header.

### Drill list
A hairline-ruled list under a 22px Inter 700 title (`<label> · n lines`), newest line first.
- **Row:** a full-width button with the game sentence in Inter 15px and the forensic mono row in Muted 13px. It opens the record in the console's right-side forensic drawer.
- **States:** hover is the inset Bone hairline; press is a 6% Bone wash.
- **Announcement:** opening a drill is announced once through a polite status element. The list itself is not a live region, so a busy stream never re-announces it.

### Export controls
Square outlined buttons, 44px tall with 4px corners, a 55% Bone border, and Inter 700 16px. The border goes full Bone on hover, and on press the button fills Bone with Ink text.

### Motion
Only state changes move. The drill list fades in over 180ms, and the forensic drawer fades and slides 16px over 200ms, both on the snap curve and through `@starting-style`, so nothing animates on load. Numbers never animate. Reduced motion removes every transition.

### Named Rules
**The Alert Only On Breach Rule.** On Command, Refusal Red appears only where an attack was not blocked or moved money: those counts, their cents, the words `not stopped`, and a total that falls short. Blocked counts and zero values stay Bone, and the words always say it as well as the colour.

**The Real Columns Rule.** Every number on Command comes from a line in the window or from this process's registry and policies. A column the comp did not draw stays if the data has it; a value the comp invented never ships.

## Do's and Don'ts

### Do:
- **Do** draw the world at an integer scale and crop it around the booth when it does not fit.
- **Do** snap every plate and frame to the 16 world colours before shipping it, and embed its generation prompt and request id in the PNG.
- **Do** carry pass and deny in words and shape as well as colour: VERIFIED / DENIED, the joined or split seal, the struck hash.
- **Do** put Ink text on Refusal Red, never Bone.
- **Do** label honest seams: `template attack` against `open-weights attacker`, TEMPLATE against MODEL, the layer that refused.
- **Do** keep every word as live text over the canvas.

### Don't:
- **Don't** use Verify Green for anything but a verified decision.
- **Don't** animate the ledger, the counters or any number. Motion belongs to the verdict and the world.
- **Don't** add cards, rounded bubbles, shadows or containers around the world. Tags are square Ink.
- **Don't** smooth, stretch or sub-pixel-position the world.
- **Don't** paint words into a plate. The booth sign is DOM text.
- **Don't** track mono tighter than −0.04em, or set world type under 14px.
