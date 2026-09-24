# 🔐 Semgrep Onboarding Guide

Welcome to the Semgrep Static Analysis Integration! This guide will help you understand how Semgrep is integrated into our development workflows and how to get started quickly in your IDE.

---

## 🚀 What is Semgrep?

Semgrep is a lightweight static analysis tool that scans code for security vulnerabilities, bugs, and enforceable best practices using custom or community-written rules.

---

## 🧠 How It Works

We have:
- Developed 20+ high-confidence, critical rules.
- Integrated Semgrep into:
  - **VS Code** (via extension)
  - **IntelliJ/JetBrains IDEs**
- Automated scans in our **CI/CD pipeline via Jenkins**.

---

## 🧩 Rule Structure

Rules are grouped and versioned inside the `SEMGREP/` directory:

SEMGREP/
├── 20 high confidence rules/
├── CWE-400 (DOS)/
├── go/
├── java/
├── kotlin/
├── python/
└── swift/


Each rule includes:
- An `id`
- Severity level (`INFO`, `WARNING`, or `ERROR`)
- Metadata (e.g., `cwe`, `owasp`)
- Code pattern

---

## ⚙️ IDE Setup

### ✅ VS Code
1. Install **Semgrep** extension from the Marketplace.
2. Reload VS Code.
3. Open a file in the repo — Semgrep will auto-run using `.semgrep.yml`.

### ✅ IntelliJ (JetBrains)
1. Install the **Semgrep Plugin**.
2. Enable code inspections or use Semgrep from the context menu.
3. Ensure your project root contains `.semgrep.yml`.

---

## 🧪 CI Integration Summary

| Branch      | Rule Coverage          | Pipeline Behavior                    |
|-------------|------------------------|--------------------------------------|
| `stage`     | All rules              | Fails on High/Critical (`--error`)   |
| `main`      | High/Critical only     | Monitor mode only (no failure)       |

---

## 🚨 Developer Expectations

- Address High/Critical issues **before pushing to stage**.
- Use Semgrep in your IDE to detect issues early.
- You may use `.semgrepignore` to suppress intentional or false-positive alerts.

---

## 🙋 FAQs

**Q: I see a false positive. What should I do?**  
A: Raise an issue in the security channel or annotate the code with `// nosem` to ignore.

**Q: How do I ignore a file/folder?**  
A: Use `.semgrepignore`.

---

## 📞 Questions?

Contact the security team 