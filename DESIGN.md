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
  hairline: "rgb(246 244 238 / 0.14)"
  raised: "#16181C"
  register-band: "#5C5E62"
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
    fontSize: "max(14px, calc(var(--scale) * 6px))"
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
  panel-head:
    fontFamily: "Inter, system-ui, sans-serif"
    fontSize: "21px"
    fontWeight: 800
    lineHeight: 1.2
  glance-title:
    fontFamily: "Inter, sans-serif"
    fontSize: "32px"
    fontWeight: 700
    lineHeight: 1.3
  glance-body:
    fontFamily: "Inter, sans-serif"
    fontSize: "28px"
    fontWeight: 400
    lineHeight: 1.3
  glance-action:
    fontFamily: "Inter, sans-serif"
    fontSize: "36px"
    fontWeight: 700
    lineHeight: 1.3
rounded:
  none: "0px"
  strip: "4px"
  disc: "50%"
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
  withheld-chip:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.muted}"
    rounded: "{rounded.none}"
    padding: "4px 12px"
---

# Design System: Mandate Console

## Overview

**Creative North Star: "The Teller Window"**

The console is one small pixel world seen through a dark frame. Meta's agents work in an office on the left, the bank branch sits on the right, and between them stands a teller booth with the Mandate seal on its face. Every request walks to that window. A verified request joins the seal's halves with a green seam. An attack is refused: the halves shake apart, a red bar drops under the booth, and the intruder is thrown back. Everything around the world is dark security: Ink ground, Bone monospace labels, one-pixel hairlines, and a ledger of real events below.

The pixel world carries the warmth and the motion. The chrome stays quiet so the verdict at the booth is always the loudest thing on screen. Text is never painted into the world: tags, bubbles, the alert, the sign and every ledger cell are live DOM text set over the canvas, so they stay sharp, selectable and spoken. The brand commitments behind the palette and type (Ink and Bone, Verify reserved for verified states, Inter with JetBrains Mono, "dark security + pixel soul") are stated in `PRODUCT.md`. The surface's direction contract is `.impeccable/surfaces/console-index-html.md`.

The same world reaches four more surfaces, each quieter than the last. Command (`console/command.html`) is the posture register with no scene. The explorer (`console/explorer.html`) is the teller window seen from the public side, with the small booth as its only scene element. The holder page (`console/holder.html`) is a cheque written on the holder's own phone. The glasses page (`webapp/`) is a 600×600 glance on a pure black ground. All five share one base: Ink and Bone, the 2px Bone focus ring, Bone selection, Muted scrollbars, and the readability floor below.

**Key Characteristics:**
- An integer-scaled 444×164 pixel world at the centre of the first viewport, the booth always centred.
- A 16-colour duotone-green world palette, separate from the UI palette.
- Green means verified and red means refused, and nothing else uses either.
- Square Ink tags with Bone monospace text, and no rounded bubbles.
- One authored motion moment, the seal's verdict. The world drifts on its own; the proof surfaces never move.
- Every text run is at least 14px at 1440×900, and every hero signal at least 18px.

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
- **Hairline** (`hairline`): Bone at 14%, every one-pixel rule and frame.
- **Raised** (`raised`): one step off Ink, for Command's provenance strip and raised rows. It still reads as Ink.
- **Register Band** (`register-band`): the header band of Command's register. Bone on it is 5.1:1.
- **Read tint** (Bone mixed 82% over Ink, 10:1): sentences meant to be read rather than skimmed, such as the holder's seam line, Command's Definition summaries and its `none in this window` values. It is never Verify.
- **Glasses ground** (pure black, `#000000`): the glasses page alone. Its display adds light, so black is the only ground that disappears; it carries Bone, Muted, Verify and Alert and nothing else. Pure black never grounds a console page.

### Browser surfaces
Every page declares `color-scheme: dark`. Selection is Bone with Ink text. The caret and the native accent colour (range inputs, checkboxes) are Bone. Scrollbars are a Muted thumb on an Ink track, 10px wide where the engine allows a width.

### World palette
- **World 0–15** (`world-0` … `world-15`): the only colours a plate or frame may contain. Every generated raster is snapped to them by block majority before it ships. They are near-black greens through pale mint, two olive-golds for the bank desk, and a warm off-white that the booth face shares.

### Named Rules
**The Green Means Verified Rule.** Verify appears only where a gate decision verified something. A denied count stays Bone.

**The Two Palettes Rule.** UI colours never enter the world, and world colours never style the UI. The one bridge is the booth face, which the seal borrows from the plate.

**The Withheld Is Not A Verdict Rule.** A field that was not checked against anything is an Ink chip ringed in Muted (2px inset) with its word in Muted. It never takes Verify, Alert or the Muted fill of a link left unchecked, so it reads as neither a pass, a failure nor a skipped step.

## Typography

**Display Font:** none. The wordmark is the brand's white horizontal SVG lockup, shipped with the console as `mandate-horizontal-white.svg`.
**Body Font:** Inter (with system-ui), for drawer headings.
**Label/Mono Font:** JetBrains Mono (with ui-monospace), for every label, row, tag and number.
**World Signage:** Press Start 2P, loaded lazily and used only for the booth sign.

**Character:** a technical mono voice that reads like a ledger, set against one piece of pixel signage that belongs to the world. All three faces are self-hosted from pinned `@fontsource` packages, latin subset. The weights shipped are Inter 400, 700 and 800, JetBrains Mono 400 and 700, and Press Start 2P 400. Inter 800 is reserved for the explorer's panel heads. No other weight is loaded, so none may be set.

### Hierarchy
- **Counters** (400, 20px, line-height 1, tabular numerals): `verified · denied · p50` in the top bar. 16px on phones.
- **Ledger row** (400, 22px, 31px pitch, tabular numerals): `time · actor · sentence · hash · verdict` plus a glyph. 16px with a 24px line on phones.
- **World tag** (400, `max(14px, scale × 19px / 3)`, −0.04em): names over figures and attacker bubbles. It follows the stage's integer scale and is 19px at 3×.
- **Alert** (700, `max(14px, scale × 6px)`, −0.04em): the refusal sentence under the booth. 18px at 3×, 24px at 4×, and 14px at 2× (phones).
- **Booth sign** (Press Start 2P 400, `max(14px, scale × 4.8px)`, +0.08em): `TELLER`.
- **Label** (400, 14px, +0.02em): stream state, GAME / FORENSIC, the TEMPLATE / MODEL origin badge.
- **Headline** (Inter 700, 22px, 1.2): the forensic drawer's title.
- **Body mono** (400, 14px, 1.5): forensic records, wrapped anywhere.
- **Panel head** (Inter 800, 21px, 1.2): the explorer's receipt label and panel headings.
- **Glance** (Inter, on the glasses page only): the title at 700 32px, body at 400 28px on a 1.3 line, the Approve and Unpair actions at 700 36px, and mono data (fields, hash, device) at 20px. These are sized for a 600×600 display read at a glance, and they do not scale down.

### Named Rules
**The Readability Floor Rule.** At 1440×900 every text run on every console page is at least 14px, and every hero signal (the verdict, the amount, a metric value, the alert at 3×) is at least 18px. In-world type follows the stage scale but never drops under 14px. Only narrower layouts step below the floor: Command's compact tables at 1100–1380px (13.5px, with 12px in their longest column); and at ≤720px Command's provenance line (13px) and stacked column names (10.5px), and the explorer's step numbers and marks (13px).

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

The page is flat. Depth lives inside the pixel world, in the plates' own perspective and shading. The UI uses no drop shadows. Stacking is by order alone: world canvas, overlay of tags and bubbles, booth and seal, alert, and the forensic drawer fixed over everything. The ledger's oldest visible row fades across the strip's open top edge through a 31px mask. That is the only gradient, and it marks history running out of view, not decoration. Hover on a row is a 1px inset Bone hairline (`box-shadow: inset 0 0 0 1px`), so the row pitch never changes. The only other inset is the withheld chip's 2px Muted ring. Where a page needs a second plane, it lifts by tone, not shadow: Command's Raised rows and the explorer's panels, which sit on a 3.5% Bone wash inside a 42% Bone frame, with a 7.5% Bone band for the gate key row.

### Named Rules
**The Flat Chrome Rule.** No shadows, glass or glows on UI. If something needs to stand forward, it gets Ink behind it and a Bone hairline around it.

## Shapes

Corners are square: tags, bubbles, buttons, badges, the alert bar, the held row, the drawer and every explorer panel and chip are all 0px. Three shapes are rounded, each for a reason:
- The ledger strip has 4px corners at the bottom only. Its top edge is open, so its floor rule reads as the base of the list.
- Controls the hand holds take 4px corners (`strip`): Command's export buttons, the holder page's request slip and buttons, and the glasses page's buttons and shown box. The holder's funds stamp is 3px.
- The explorer's step numbers and their pass and fail marks are discs (`disc`, 50%) with a 2px ring, so a link's order never reads as a verdict chip.

The holder's receipt stub is Bone paper inside a 2px dashed Ink edge, a perforation. Rules are 1px Bone at 14% opacity. The seal is the brand's Reunion mark: two stepped halves of an Ink square on the booth face. At rest the halves sit 8 units apart in the mark's 256 grid. A refusal opens them to 16 units and shakes them ±6 units. A verification closes them over 133ms. The mark is framed to its refused extent (16 to 240), so the halves fill the face's height without clipping.

## Components

### Focus ring
Every focusable element on every console page takes the same ring: a 2px solid Bone outline, offset 2px, on `:focus-visible` only. It is never recoloured. The explorer's paste box offsets its ring 6px so it clears the text. The glasses page draws the ring at 4px, offset 2px, because its display is read at arm's length.

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

### Held row
The payment waiting for the holder is a held ledger row, pinned flush under the stage over the ledger strip so the booth, its seal, the alert bar and the walkers stay uncovered.
- **Style:** Ink with a 1px Bone rule, `min(928px, 100% − 20px)` wide, mono 18px on a 22px line, an Inter 700 21px title.
- **Order:** amount (mono 700 30px, tabular) and payee (24px) first, then the steps as one line, the seven consent fields as two column pairs of 16px mono, the shown digest, and the gate's digest set beneath it at 18px so its eight groups line up.
- **Steps:** each is a word and a drawn mark as well as a colour: a filled square done, a hollow square current (Bone 700), the seal's refusal seam failed (Alert), no mark yet to come (Muted).
- **Status:** a ringed word in `currentColor`, Muted while someone still has to act, Verify once paid, Alert on a refusal, an expiry or a denial.
- **Settled:** the row folds to its title and status, and the title unfolds it.
- **≤720px:** it leaves the overlay and sits under the stage at full width as one column, at 16px; the page scrolls, never sideways.

### Attacks panel and kill-cam
- **Attacks panel:** fixed left under the top bar, `min(360px, 100%)`, Ink with a hairline right edge. Each attack, scenario and model control is a square full-width button at least 32px tall, mono 700 14px, with a hairline-ringed origin badge at its end. Disabled launchers drop to Muted with a dashed hairline.
- **Kill-cam:** fixed right, `min(520px, 100%)`, over the forensic drawer, which narrows to match. The tape is a 300px pixelated canvas under static scanlines (6% Bone every 3px, never animated). Its steps are 14px mono rows: the word passed in Verify, failed in Alert with an Alert rule, skipped and unreached in Muted, and the current step marked by a 2px Bone left edge. At 720px and wider the still sits beside its caption.

### Motion
Five named moments are the system's motion tokens, served to CSS as `--motion-<name>` and to the seal's code in milliseconds:
- **Seam snap** (`seam-snap`, 133ms linear): the seal's halves close from 8 to 0 units of the mark's 256 grid and stop dead. The green seam is lit from the first frame.
- **Mismatch open** (`mismatch-open`, 100ms linear): on a denial the halves part from 8 to 16 units and stay apart. The Alert seam replaces the gap from the first frame.
- **Mismatch shake** (`mismatch-shake`, 80ms `steps(1, end)`): four lateral beats of 6 units, left first, then still.
- **Alert enter** (`alert-enter`, 120ms `cubic-bezier(0.16, 1, 0.3, 1)`): the alert bar's ink fades from opacity 0 to 1 in its already-placed box, with the seal's verdict.
- **Bubble enter** (`bubble-enter`, 120ms `cubic-bezier(0.16, 1, 0.3, 1)`): each sentence bubble fades in, in its final box, through `@starting-style`.

The curve `cubic-bezier(0.16, 1, 0.3, 1)` is the snap: fast in, a dead stop, no overshoot. Every authored state change on the other pages uses it and moves colour or opacity, never a box, with one exception: Command's drawer, which slides 16px.
- **The world's own drift:** walkers move at 96 native px/s with 120ms walk frames. Ambient frames cycle at 140–400ms. The vault opens over 1.5s.
- **Never animated:** the ledger, the counters, the top bar and every number. Elsewhere a proof surface may settle its colour (the explorer's verdict and marks, 180ms) or fade in once on arrival (the holder's stub), but no proof surface ever moves.
- **Reduced motion:** every CSS transition and animation is stilled. Walks and frame cycles stop and the visitor appears at the booth in one step. The seal keeps its own states: `wait`, `verify` and `deny` still land, at once, so the verdict is never lost with the motion.

## Command

`console/command.html` is the executive posture view, a control register for agent actions. It lives in the console's settled world without the pixel scene: Ink ground, Bone text, Muted secondary, hairline rules, JetBrains Mono for every number, hash and seq. Its direction contract is `.impeccable/surfaces/console-command-html.md`. Every value on it is computed from the console's retained lines and this process's registry and policies, and every metric opens down to those lines.

### Layout
- **Top bar:** the wordmark (48–50px), the view name in Muted uppercase 17px Inter 700 with +0.1em tracking, and Export Markdown and Export JSON at the right. The bar closes on a 3px Muted rule, the only heavier rule on the page.
- **Provenance strip:** one Bone mono 700 15px line on Raised naming the window, where it starts and the registry it rests on. An empty registry reads `registry empty`, never a root over 0 entries. Stream state and the link back to the live console sit at its right.
- **Metric band:** nine equal cells, six to a row (three per row below 1100px), divided by hairlines, then a hairline under the band.
- **Control register:** the framework table, grouped by framework.
- **Compact tables:** attacks by kind and denials by layer side by side, split by a vertical hairline.
- **Drill list:** under the tables, opened on demand.

The page gutter is `clamp(16px, 2.92vw, 48px)`. Columns are fluid from 1280 to 1600. A 1100–1380px step shrinks the compact tables' type so both stay whole beside each other.

### Metric cell
- **Label:** Inter 700 15px on a 19px line, balanced.
- **Value:** JetBrains Mono 700 at `clamp(36px, 3.34vw, 56px)`, tabular.
- **Shares and gate time:**
  - Shares (consent, attribution) use `clamp(20px, 1.7vw, 28px)` and render as two unbreakable spans, the count then `· share`, so a line never ends on the dot.
  - Gate time sets its two percentiles on one line at 14px, with the Muted 14px sample count under them.
  - The bank check reads as a 15px mono sentence (count, rail and time), in Alert only when a payment is unbacked.
  - A value that says the window has none (`none in this window`) drops to a 15px Bone 82% sentence.
- **Colour:** the verified value is always Verify. Attacks not blocked and Moved by attacks take Alert only when they are not zero (`data-zero="false"`). Every other value is Bone.
- **Below the value:** the Definition disclosure, and a `Show the n lines` drill button in Muted 14px underlined mono.

### Definition disclosure
A `summary` reading Definition, followed by an authored 14px info mark (ring, dot and stem, a data-URI mask filled with `currentcolor`). Opening it lays the exact definition, in Inter 14px, over the page in a 320px Ink box with a 40% Bone hairline, so the band never shifts. The last three cells open leftward. The attacks and layers tables carry the same disclosure beside their headings.

### Control register
- **Heading:** an uppercase Inter 700 18px heading tracked +0.08em, with `17 provisions` (singular for one) in Muted 14px mono under it.
- **Disclaimer and applicability:** right-aligned in Muted Inter 14px. The applicability line sits above the table it calls "below".
- **Header band:** Register Band, with Bone uppercase Inter 700 14px labels (5.1:1).
- **Rows:** Raised, separated by 2px Ink. Body cells are 14px.
  - The framework name is in Inter 700 15px, said once per group; repeats are transparent but still spoken.
  - The rule between groups is 40% Bone.
  - Evidence is in mono 700.
  - Source is a mono link.
- **Size:** at desktop the register is a 275px scroll box with a sticky header. Its foot fades over 48px until it is scrolled to its end (`data-at-end`).
- **≤720px:** each provision stacks as a block. Every value carries its column name above it from `data-label`, in Muted 10.5px uppercase mono, with no nested scroll.

### Compact tables
- **Rows and header:** 22px rows on Raised with 2px Ink gaps, 15px. The header is Muted 14px uppercase mono.
- **Text:** the kind or layer name is Inter 700 15px; numbers are mono and tabular, right-aligned.
- **Attacks total row:** below a 40% Bone rule, it counts only kinds attempted in the window, so an untried kind is never called blocked (`all 7 kinds blocked`, `all 3 attempted kinds blocked`, `3 of 4 attempted kinds blocked`, `no attacks attempted`).
- **An attack kind that got through:**
  - Its Not blocked and Moved cells turn Alert.
  - Stopped at reads `not stopped` in Alert 700.
  - The total names how many kinds held, in Alert.
- **≤720px:** the tables scroll sideways inside their section. The name column is sticky (`left: 0`, 104–120px, wrapping), on `--raised` in the body and on Ink in the header.

### Drill list
A hairline-ruled list under a 22px Inter 700 title (`<label> · n lines`), newest line first.
- **Row:** a full-width button with the game sentence in Inter 15px and the forensic mono row in Muted 14px. It opens the record in the console's right-side forensic drawer.
- **States:** hover is the inset Bone hairline; press is a 6% Bone wash.
- **Announcement:** opening a drill is announced once through a polite status element. The list itself is not a live region, so a busy stream never re-announces it.

### Export controls
Square outlined buttons, 44px tall with 4px corners, a 55% Bone border, and Inter 700 16px. The border goes full Bone on hover, and on press the button fills Bone with Ink text.

### Motion
Only state changes move. The drill list fades in over 180ms, and the forensic drawer fades and slides 16px over 200ms, both on the snap curve and through `@starting-style`, so nothing animates on load. Numbers never animate. Reduced motion removes every transition.

### Named Rules
**The Alert Only On Breach Rule.** On Command, Refusal Red appears only where an attack was not blocked or moved money, a Nimbus step ran when it should not, or a payment had no bank backing: those counts, their cents, the words `not stopped`, an unbacked bank check, and a total that falls short. Blocked counts and zero values stay Bone, and the words always say it as well as the colour.

**The Real Columns Rule.** Every number on Command comes from a line in the window or from this process's registry and policies. A column the approved design did not draw stays if the data has it; a value the design invented never ships.

## Explorer

`console/explorer.html` is the public proof explorer: a receipt goes in, and every link of its proof is checked in this browser, in order, until the first one that breaks. Its direction contract is `.impeccable/surfaces/console-explorer-html.md`. It is the console's world, quieter: no pixel scene except the small booth (85×111px, pixelated) at the right of the top bar, whose seal stamps the page's verdict.

### Layout
- **Top bar:** 116px tall, the lockup at 63px, the page name in a Bone-ruled mono 700 17px uppercase box, the way back to the console as a Muted one, then the booth.
- **Gate key row:** a 7.5% Bone band between a 42% frame and a hairline, mono 17px. The key reads mono 700 18px and shows in full while it is edited.
- **Two columns** (692 : 581, 24px apart, gutter `clamp(16px, 5vw, 72px)`): the receipt and its chain on the left; what it reveals, what is never in a receipt and the auditor share on the right. Below 960px it is one column with the verdict first under the paste.

### Verdict
A mono 700 18px bar under the paste. A failure is an Alert bar with Ink words, a pass a Verify bar with Ink words. Its label is stamped on Ink, so the word itself carries the colour. A withheld verdict keeps a Bone label on Ink. The booth's seal follows it: apart while it waits, split with an Alert seam on a failure, joined with a Verify seam on a pass.

### Chain steps
One row per link: a numbered disc (28px, 2px Muted ring, Muted mono 700 15px numeral), the link name in Inter 700 20px, a 1px frame rule, its note in Muted Inter 14px, and a mark at the end.
- **Pass and fail:** the disc fills with Verify or Alert and carries an Ink tick or cross.
- **Marks:** chips at least 76px wide, mono 700 15px, Ink words on Verify (pass), Alert (fail) or Muted (not checked).
- **Withheld:** the withheld chip. Its note moves under the row.
- **Failure detail:** the breaking step's reason opens under it on the band, in Bone 18px.
- **Settling:** the verdict, discs and marks change colour over 180ms on the snap. Nothing moves.

### Panels and controls
- **Panels:** the 3.5% wash inside the 42% frame, square, with Inter 800 21px heads.
- **Reveals:** Inter 700 16px names against mono 16px values. A withheld value is Muted.
- **Choices:** 22px square checkboxes with a 2px Bone ring, filling Bone with an Ink tick.
- **Buttons:** square, framed, mono 700 17px. Hover lays the band; press fills Bone with Ink text.

## Holder

`console/holder.html` is the holder's own device: they state a payment, sign the cheque it fills, and keep the stub. Its direction contract is `.impeccable/surfaces/console-holder-html.md`. It has no pixel scene. The whole page is one 432px column at every size, gutter `clamp(16px, 6.5vw, 28px)`, set in mono 15px on a 1.4 line and tracked at the floor, −0.04em.
- **Heading:** mono 700 36px, balanced.
- **Request slip:** a Bone-ruled box with 4px corners holding the centred request text and its three ways in (Read it, Record, the WAV clip) on one line, down to 379px wide, where the clip takes its own row.
- **Buttons:** at least 41px tall, Bone 1px border, 4px corners, mono 700 14px. Hover lays a 6% Bone wash, press and a live recording fill Bone with Ink text, and disabled drops to Muted on a 40% border.
- **Cheque fields:** a two-column mono 15px list, Muted names against Bone values.
- **Stub:** Bone paper with Ink mono 14px inside the dashed perforation. The funds line is an Ink stamp on it, so Verify keeps its contrast; its word turns Verify with a ring-and-tick mark only on a statement verified on this device, and Alert when it fails.
- **Status sentences:** progress in Muted, a refusal in Alert with its words. The seam line is the read tint, never Verify.
- **Arrival:** the cheque fields and the stub fade in over 120ms on the snap; the funds stamp lands 180ms after its paper, so the verified line settles last. No box moves.

## Glasses

`webapp/` is the approval glance on the holder's glasses: a 600×600 display, padded 24px, on the pure black ground. It shows what is to be approved and offers two actions, nothing else.
- **Type:** the glance sizes, Inter title 32px, Inter body 28px, the Approve and Unpair buttons at 36px full width, and mono 20px fields, with the hash and device in Muted.
- **Approve:** a Bone fill with black text, 4px corners and a 4px Bone border. Disabled it turns black with a Muted word and border.
- **Unpair:** the same button in reverse: black fill, Muted word and border.
- **Shown box:** a 2px Bone border with 4px corners around the text being approved. It takes no room while it is empty but stays in the tree so it can announce.
- **Focus:** the 4px Bone ring.

## Do's and Don'ts

### Do:
- **Do** draw the world at an integer scale and crop it around the booth when it does not fit.
- **Do** snap every plate and frame to the 16 world colours before shipping it, and embed its generation prompt and request id in the PNG.
- **Do** carry pass and deny in words and shape as well as colour: VERIFIED / DENIED, the joined or split seal, the struck hash.
- **Do** put Ink text on Refusal Red, never Bone.
- **Do** label honest seams: `template attack` against `open-weights attacker`, TEMPLATE against MODEL, the layer that refused.
- **Do** keep every word as live text over the canvas.
- **Do** give every focusable element the 2px Bone ring offset 2px (4px on the glasses page).
- **Do** hold every text run at 14px or more at 1440×900, and every hero signal at 18px or more.
- **Do** mark a withheld field as an Ink chip with a Muted ring and a Muted word.

### Don't:
- **Don't** use Verify Green for anything but a verified decision.
- **Don't** animate the ledger, the counters or any number. Motion belongs to the verdict and the world.
- **Don't** add cards, rounded bubbles, shadows or containers around the world. Tags are square Ink.
- **Don't** smooth, stretch or sub-pixel-position the world.
- **Don't** paint words into a plate. The booth sign is DOM text.
- **Don't** track mono tighter than −0.04em, or set world type under 14px.
- **Don't** use pure black anywhere but the glasses page's ground.
- **Don't** load or set a weight the system does not ship (Inter 400/700/800, JetBrains Mono 400/700, Press Start 2P 400).
