# KPMG CTF 2026 — Campus Edition Writeups

**Event:** KPMG Capture The Flag 2026  
**Date:** October 9–11, 2026  
**Total:** 190 pts | 13 documented solves across 6 categories

---

## Solved Challenges

| Challenge | Category | Points | Writeup |
|-----------|----------|--------|---------|
| TrollClock | Web | 10 | [trollclock.md](web/trollclock.md) |
| AcmeBank Assistant | AI/LLM | 10 | [acmebank-assistant.md](ai-llm/acmebank-assistant.md) |
| SecureBot Support | AI/LLM | 10 | [securebot-support.md](ai-llm/securebot-support.md) |
| Corrupted Vision | Crypto / Stego | 30 | [corrupted-vision.md](cryptography/corrupted-vision.md) |
| Onion | Crypto | 10 | [onion.md](cryptography/onion.md) |
| Secure Vault | Rev Eng | 20 | [secure-vault.md](reverse-engineering/secure-vault.md) |
| Logic Bypass | Rev Eng | 10 | [logic-bypass.md](reverse-engineering/logic-bypass.md) |
| Baud Intentions | OT/IoT | 10 | [baud-intentions.md](ot-iot/baud-intentions.md) |
| Last Will | OT/IoT | 20 | [last-will.md](ot-iot/last-will.md) |
| Matrix Reload | OT/IoT | 30 | [matrix-reload.md](ot-iot/matrix-reload.md) |
| Vodoo Spirit of Death - 1 | Infra | 10 | [voodoo-spirit.md](infra/voodoo-spirit.md) |
| VaultDocs - 1 | Infra | 10 | [vaultdocs.md](infra/vaultdocs.md) |
| Healthy Hijack - 1 | Infra / OT | 10 | [healthy-hijack-1.md](infra/healthy-hijack-1.md) |

> **Note:** Two early "welcome" flags (10 pts) were captured but exact steps weren't recorded — likely page-source inspection and `Ctrl+A` white-on-white text reveal.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| `nmap` | Port scanning & service enumeration |
| `gobuster` | Directory brute-forcing |
| `curl` | HTTP probing & manual requests |
| `Burp Suite` | Intercepting/modifying web traffic |
| `CyberChef` | Encoding/decoding chains (Base64, hex, Atbash, XOR) |
| `strings` / `nm` / `objdump` | Binary analysis & reverse engineering |
| `mosquitto_pub` / `mosquitto_sub` | MQTT broker interaction |
| `redis-cli` | Redis enumeration |
| `Python` | Custom scripts for brute-forcing & automation |
| `GTFOBins` | Privilege escalation reference |

---

## Key Takeaways

- **Recon first** — `nmap`, `gobuster`, and raw page source before trusting any UI.
- **Read everything** — config backups, notes files, and source code leak more than just creds.
- **Test what they missed** — blocklist bypasses often come down to one forgotten character (e.g. `\n` vs `;`).
- **Automate probing** — small scripts beat manual CLI for timing-sensitive or repetitive tasks.
- **Post-shell checklist** — `sudo -l`, SUID binaries, `/etc/crontab` — always.
- **Chain services** — most flags followed: recon → leaked cred/misconfig → pivot → flag.

---

*Flags redacted — writeups shared for educational purposes only.*
