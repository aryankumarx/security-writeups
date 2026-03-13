# Lab 2: SQL Injection Login Bypass

**Difficulty:** Apprentice  
**Date:** March 2026

## Goal
Log in as administrator without knowing the password.

## What I Found
The login form was vulnerable to SQL injection. The backend query probably looked like:
```sql
SELECT * FROM users WHERE username = 'INPUT' AND password = 'INPUT'
```

No input sanitization, direct string concatenation.

## My Approach
Instead of trying `' OR 1=1--` (which logs you in as the first user - could be anyone), I targeted the admin account specifically.

Used `administrator'--` in the username field:
- `administrator` - targets the admin account
- `'` - closes the username string  
- `--` - comments out the entire password check

Put anything in the password field since it gets ignored.

## Payload
**Username:**
```
administrator'--
```

**Password:** (anything)

**Result:**
```sql
SELECT * FROM users WHERE username = 'administrator'--' AND password = 'whatever'
```

The query becomes `SELECT * FROM users WHERE username = 'administrator'` and the password verification never happens.

## Key Takeaway
Being specific is better than blind injection. `administrator'--` is cleaner than `' OR 1=1--` because you're targeting exactly who you want to be, not just logging in as whoever comes first in the database.

 Also learned that `--` doesn't just clean up syntax - it can completely neutralize security checks.

---

## Mitigation

**For Developers:**

- Use parameterized queries (prepared statements) instead of string concatenation.

- Implement strict input validation for username and password fields.

- Hash and salt passwords using secure algorithms like `bcrypt` or `Argon2`
- Apply the principle of least privilege to database accounts.
- Implement login rate limiting and account lockout to prevent brute-force attempts.

---
**Example Fix (Python):**
```python
### ❌ #Vulnerable
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

### ✅ Secure

query = "SELECT * FROM users WHERE username = ?"
cursor.execute(query, (username,))
```