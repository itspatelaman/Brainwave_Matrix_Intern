# 🔎 Phishing Link Scanner

A professional-grade phishing detection tool built with Python and CustomTkinter. This scanner classifies URLs as **Safe**, **Suspicious**, or **Malicious** using:

- Threat scoring based on phishing indicators
- VirusTotal reputation API
- URLScan.io API analysis
- Support for unshortened links
- Clean, dark-themed GUI interface

---

## 🚀 Features

- ✅ Detect phishing based on:
  - IP-based URLs
  - Suspicious keywords (e.g., `login`, `update`, `bank`, etc.)
  - URL shorteners (`bit.ly`, `tinyurl`, etc.)
- 🔍 Real-time checks with VirusTotal & URLScan.io APIs
- 📂 Supports bulk scanning from `.txt` files
- 💾 Export scan reports
- 🎨 Color-coded GUI:
  - 🟢 Green for Safe
  - 🟠 Orange for Suspicious
  - 🔴 Red for Malicious

---

## 📸 GUI Preview

![Screenshot](screenshot.png)

---

## 🧠 How It Works

1. **URL is entered or loaded from file**
2. **URL is unshortened**, if applicable
3. **Threat score is calculated** based on:
   - IP-based pattern
   - Presence of phishing keywords (e.g., `paypal`, `secure`, `verify`)
   - Whether it's shortened
4. **Reputation checks** via:
   - **VirusTotal API**
   - **URLScan.io API**
5. **Final classification**:
   - Score ≥ 60: 🚨 Malicious
   - 25 ≤ Score < 60: ⚠️ Suspicious
   - Score < 25: ✅ Safe
6. **Output shown in GUI** with appropriate colors

---

## 🛠️ Tech Stack

- Python 3.10+
- [CustomTkinter](https://github.com/TomSchimansky/CustomTkinter)
- [Requests](https://pypi.org/project/requests/)
- [validators](https://pypi.org/project/validators/)

---

## 📦 Installation

```bash
git clone https://github.com/your-github/phishing-link-scanner.git
cd phishing-link-scanner
pip install -r requirements.txt
```

## 🔐 API Keys Required ##

```bash
Create a file named .env or hardcode your keys (not recommended):
```

*VIRUSTOTAL_API_KEY* = your_virustotal_key_here

*URLSCAN_API_KEY* = your_urlscan_key_here

## ▶️ Usage ##
### Run the GUI: ###
```bash
python gui_app.py
```

### Run CLI mode: ###
```bash
python scanner.py
```

*Put the URLs in urls.txt (one per line) for batch scanning.*

## 📁 File Structure ##
```
phishing-link-scanner/
├── gui_app.py              # Main GUI
├── scanner.py              # Core logic & CLI tool
├── utils/
│   ├── unshortener.py
│   ├── virustotal.py
│   └── urlscan.py
├── urls.txt                # Input file (for CLI)
├── scan_report.txt         # Output file
└── README.md
```

## 🧪 Phishing Keywords Used ##

```
login, update, verify, account, secure, webscr,
banking, paypal, signin, security, ebay, password, confirm
```
*You can expand this list in scanner.py.*

---

## ✅ Example Output (GUI) ##

```
[URL] https://paypal-login.com/update
[Unshortened] https://paypal-login.com/update
[Status] ⚠️ Suspicious | Score: 30
[VirusTotal] VT: ✅ Clean
[URLScan.io] ✅ Found
```
------------------------------------------------------------


## ⭐ License ##
This project is licensed under the MIT License.

### ✅ Next Steps:
- Replace `your-github` and `your-profile` with your actual GitHub and LinkedIn URLs.
- Place a screenshot of the GUI in the same folder and name it `screenshot.png`.
- Add a `requirements.txt` file (if you don't have one, I can generate it for you).

Let me know if you want that `requirements.txt` or want to add badges, installation GIFs, or anything else!
