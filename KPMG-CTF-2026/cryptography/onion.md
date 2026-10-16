# Challenge Name: Onion
**Category:** Cryptography
**Points:** 10
**Difficulty:** Easy

### Description
A challenge framed around an "old system administrator who liked stacking layers," hinting that the provided file (`chall.enc`) contained several nested transformations rather than a single encryption algorithm. Living up to its name, the flag turned out to be about "peeling the layers like an onion."

### Approach
1. Inspected the raw contents of `chall.enc` rather than assuming it was opaque ciphertext — found it consisted of binary groups representing standard 8-bit ASCII characters.
2. Treated this as a layered-encoding puzzle: decode one layer at a time, inspect the intermediate output after each step, and let the output's shape tell you what the next layer is.

### Solution
Worked through the stack one transformation at a time:
1. **Binary → ASCII**: converted the 8-bit binary groups into readable text, which turned out to be a Base64 string.
2. **Base64 decode**: decoding that string produced a hexadecimal string.
3. **Hex → ASCII**: converting the hex string to ASCII produced readable-but-wrong text:
   ```
   PKNT_XGU{k33o_gs3_o4b3ih_o1p3_4m_0m10m}
   ```
   Close to a flag format (`{...}` structure, leetspeak-style content) but the prefix (`PKNT_XGU` instead of `KPMG_CTF`) and the garbled words signaled one more transformation remained.
4. **Atbash cipher**: recognized the substitution pattern (each letter mapped to its mirror in the alphabet, A↔Z, B↔Y, C↔X, etc.) and applied it to the intermediate text. This produced the final, correctly-formatted flag, decoding the leetspeak phrase "peel the layers like an onion" — matching the challenge's name and hint.

Full chain: `Binary → ASCII → Base64 → Hex → ASCII → Atbash → flag`

### Flag
`[REDACTED]`

### Proof
![Onion — final Morse decode revealing the flag](../screenshots/onion-morse.png)

### What I Learned
- Never assume an unknown file is strongly encrypted — inspect it first. Binary groupings, Base64 character sets, and hex digit patterns are all visually recognizable and point directly to the next decoding step.
- Decode one layer at a time and actually look at each intermediate result rather than trying to chain transformations blindly — the intermediate `PKNT_XGU{...}` output looked *almost* right, which was the signal that exactly one more (substitution-cipher) layer remained rather than a different encoding entirely.
- Hex and Base64 are encodings, not encryption — they're always reversible with no key required, so treat them as "free" layers to peel before looking for anything cryptographically meaningful.
- Classical substitution ciphers like Atbash can still show up as the final layer even in a modern-encoding-heavy challenge; recognizing the letter-mirroring pattern (A↔Z) is usually enough to identify it on sight.
- Always validate decoded output against the expected flag format (`KPMG_CTF{...}`) — a near-miss like `PKNT_XGU{...}` is a strong clue that one more reversible step remains, not that you've made an error.
