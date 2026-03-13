# PortSwigger Web Security Academy - Lab Writeups

![PortSwigger](https://img.shields.io/badge/PortSwigger-Web%20Security%20Academy-orange)
![Status](https://img.shields.io/badge/Labs%20Solved-4-brightgreen)
![Category](https://img.shields.io/badge/Focus-SQL%20Injection-blue)

## 📖 About

This repository contains my writeups and solutions for [PortSwigger Web Security Academy](https://portswigger.net/web-security) labs. Each writeup includes:

- **Detailed methodology** with step-by-step approach
- **Payload explanations** showing how and why they work
- **Developer perspective** on what mistakes caused the vulnerability
- **Mitigation techniques** to prevent similar issues
- **Real-world impact** and practical takeaways

## 🎯 Purpose

I created this repository to:
- Document my learning journey in application security
- Share knowledge with the security community
- Build a reference for common attack patterns
- Practice technical writing and vulnerability reporting

## 📚 Lab Progress

### SQL Injection

| Lab # | Lab Name | Difficulty | Status | Writeup |
|-------|----------|------------|--------|---------|
| 1 | SQL Injection - WHERE Clause Att       ack | Apprentice | ✅ Solved | [View](./lab-01-sqli-where-clause.md) |
| 2 | SQL Injection - Login Bypass | Apprentice | ✅ Solved | [View](./lab-02-sqli-login-bypass.md) |
| 3 | SQL Injection UNION Attack | Practitioner | ✅ Solved | [View](.lab-03-sqli-union-column-count.md) |
| 4 | SQL Injection UNION-TEXT-COLUMN | Practitioner | ✅ Solved | [View](./lab-04-sqli-union-text-column.md) |


### Other Categories
*Coming soon as I progress through more labs...*

## 🛠️ Tools Used

- **Burp Suite Community Edition** - For intercepting and modifying HTTP requests
- **Browser DevTools** - For analyzing client-side behavior
- **Manual Testing** - Understanding vulnerabilities before automation

## 📝 Writeup Structure

Each writeup follows a consistent format:

1. **Lab Information** - Platform, category, difficulty, date
2. **Objective** - What the lab requires
3. **Vulnerability** - Technical explanation with developer perspective
4. **Steps** - Detailed methodology
5. **Payload** - Exact injection used with explanation
6. **What I Learned** - Key takeaways
7. **Mitigation** - How developers can fix it

## 🔗 Resources
 
### PortSwigger
- [Web Security Academy](https://portswigger.net/web-security)
- [SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- [Burp Suite Docs](https://portswigger.net/burp/documentation)
 
### Security References
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CWE Database](https://cwe.mitre.org/)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)

## 🤝 Contributing

If you spot any errors or have suggestions for improvement, feel free to:
- Open an issue
- Submit a pull request
- Reach out with feedback

## 📊 Stats

- **Total Labs Attempted:** 4
- **Labs Solved:** 4
- **Current Focus:** SQL Injection

---

**Last Updated:** March 2026  

*"Understanding vulnerabilities from both the attacker's and developer's perspective."*
