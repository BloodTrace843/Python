# LimeSurvey 6.6.4 - Authenticated RCE Exploit via Plugin Upload

> **DISCLAIMER:**  
> This tool is provided **for educational purposes only**.  
> The author does **not condone or support unauthorized access** or malicious activity.  
> Use responsibly and only on systems you have **explicit permission** to test.

---

## 📌 Description

This Python script exploits a **vulnerability in LimeSurvey version 6.6.4** that allows an **authenticated attacker** to upload a malicious plugin containing a **PHP reverse shell**. Once uploaded and activated, the attacker gains remote code execution (RCE) as the web server user.

It automates:

- Login to the LimeSurvey admin dashboard
- Upload of a ZIP archive containing a malicious plugin
- Confirmation of the plugin installation
- Execution via direct access to the plugin's PHP payload

---

## ⚙️ Features

- Auto-generates malicious plugin files (`config.xml` + PHP reverse shell)
- Authenticates to LimeSurvey using provided admin credentials
- Uploads and confirms the plugin install
- Drops a PHP reverse shell listener for incoming connections

---

## 🛠 Requirements

- Python 3.x
- `requests` module

Install dependencies:

```bash
pip install requests
