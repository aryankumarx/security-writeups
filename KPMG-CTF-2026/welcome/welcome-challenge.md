# Challenge Name: Welcome Challenge
**Category:** Welcome
**Points:** 5
**Difficulty:** Trivial

### Description
"Are you a robot? Find the flag."
(Introductory challenge, hosted on the CTF platform's own Guidelines page.)

### Approach
1. The flag was hidden in **white text on a white background** on the platform's Guidelines page (`https://kicyber.ctfd.io/guidelines`) — invisible to a normal read-through of the page.
2. Revealed it using either of two standard techniques:
   - **Select-all**: pressing `Ctrl+A` on the page highlights all text regardless of its color, making white-on-white text visible against the highlight.
   - **Inspect / View Source**: opening browser DevTools (or view-source) shows the raw HTML/text content directly, bypassing any CSS color styling entirely.

### Solution
Used `Ctrl+A` to select the entire page content, which revealed the hidden white text containing the flag. (Equivalently, inspecting the page's HTML source would show the same text directly in the DOM.)

### Flag
"[REDACTED]"

### What I learned
- Always check for "invisible" content on CTF platform pages (guidelines, rules, about pages) — white-on-white text, `display: none`, or zero-opacity elements are classic easy-win hiding spots for intro-level flags.
- `Ctrl+A` (select all) is a fast, low-effort way to surface color-hidden text without needing to open DevTools.
- Viewing page source or using browser inspection tools bypasses CSS-based hiding entirely and should be a reflexive first step on any web-based challenge, even introductory ones.
