# LimeSurvey Plugin Upload Exploit (PoC)

This Python script automates uploading a custom plugin to a LimeSurvey instance (tested on version 6.6.4).  
It requires admin credentials to perform the plugin upload.

---

## ⚠️ Legal Disclaimer

**Use this script only on systems you own or have explicit permission to test. Unauthorized use or exploitation of vulnerabilities is illegal and unethical. The author is not responsible for any misuse of this tool.**

---

## Features

- Automates login and retrieves admin session cookie
- Generates minimal plugin config XML
- Creates a plugin zip file including your custom PHP file
- Uploads and installs the plugin on the LimeSurvey instance

---

## Requirements

- Python 3.x
- `requests` library (`pip install requests`)

---

## Usage

```bash
python3 limesurvey_plugin_upload.py --file_name your_php_file.php --target http://target-limesurvey-url --username admin --password adminpass
