# Challenge Name: First Flag
**Category:** Welcome
**Points:** 5
**Difficulty:** Trivial

### Description
A second introductory/welcome-tier flag on the CTF platform. Exact challenge title and prompt text were not preserved from the original session.

### Approach
Two possible discovery methods were used/considered for this flag:
1. **Minimizing the browser window** — resizing the window smaller revealed content that was otherwise off-screen or hidden by the page's normal layout (e.g. an element positioned outside the visible viewport at full window size, which becomes visible once the layout reflows at a smaller width).
2. **Viewing page source** — the flag was also discoverable directly in the page's HTML source without needing to interact with the rendered page at all.

### Solution
The flag was recovered either by minimizing the browser window (causing a layout shift that exposed previously off-screen/hidden content) or, equivalently, by viewing the page's source code directly.

### Flag
"[REDACTED]"

### What I learned
- Responsive/fluid page layouts can unintentionally (or intentionally, in a CTF) hide content at certain viewport widths — resizing the browser window is a cheap technique worth trying when a page "looks complete" but a flag isn't visible.
- Viewing page source remains one of the fastest, most reliable ways to find content that rendering/CSS/layout might be obscuring, and should generally be tried before more involved layout manipulation.

---
> **Note:** The exact challenge title, description, and specific flag format for this entry were not fully preserved from the original conversation. This writeup reflects the discovery technique as reported, but should be reviewed/corrected against the original CTF platform entry if more precision is needed for the public writeup.
