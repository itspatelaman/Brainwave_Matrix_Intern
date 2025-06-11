import re
import validators
import os
from utils.unshortener import unshorten_url
from utils.virustotal import check_url_virustotal
from utils.urlscan import scan_url_with_urlscan  # ✅ Correct name

phishing_keywords = [
    "login", "signin", "account", "verify", "secure", "update", "bank", "ebay", "paypal",
    "password", "reset", "webscr", "confirm", "security", "invoice", "payment", "unlock",
    "limited", "expired", "suspended", "verify-now", "submit", "authentication", "validate",
    "credentials", "token", "support", "alert", "warning", "helpdesk", "recovery"
]

shorteners = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorturl.at", "cutt.ly"
]

def is_ip_address(url):
    return bool(re.match(r"(http[s]?://)?\d{1,3}(\.\d{1,3}){3}", url))

def contains_suspicious_keywords(url):
    return any(keyword in url.lower() for keyword in phishing_keywords)

def is_shortened_url(url):
    return any(shortener in url for shortener in shorteners)

def uses_placeholder_domain(url):
    return any(domain in url.lower() for domain in [".example.com", ".test", "malicious-site", ".phish", ".xyz"])

def get_threat_score(url):
    score = 0
    if is_ip_address(url):
        score += 40
    if contains_suspicious_keywords(url):
        score += 30
    if is_shortened_url(url):
        score += 20
    if uses_placeholder_domain(url):
        score += 50  # Strong signal of malicious URL
    return score

def classify_url(url):
    real_url = unshorten_url(url)
    if "[ERROR]" in real_url:
        print("[WARN] Could not unshorten. Falling back to original URL.")
        real_url = url

    score = get_threat_score(real_url)

    if score >= 60:
        status = "🚨 Malicious"
    elif score >= 25:
        status = "⚠️ Suspicious"
    else:
        status = "✅ Safe"

    vt_status = check_url_virustotal(real_url)
    urlscan_result = scan_url_with_urlscan(real_url)  # ✅ Updated function call

    return {
        "original_url": url,
        "unshortened_url": real_url,
        "score": score,
        "status": status,
        "virustotal": vt_status,
        "urlscan": urlscan_result
    }

def main():
    if not os.path.exists("urls.txt"):
        print("❌ ERROR: 'urls.txt' file not found.")
        return

    with open("urls.txt", "r") as file:
        urls = [line.strip() for line in file.readlines() if line.strip()]
    
    if not urls:
        print("⚠️ 'urls.txt' is empty.")
        return

    print("\n🔎 PHISHING LINK SCANNER RESULTS\n")

    with open("scan_report.txt", "w", encoding="utf-8") as report:
        report.write("🔎 PHISHING LINK SCANNER RESULTS\n\n")
        for url in urls:
            result = classify_url(url)
            output_line = f"{url} ➜ {result}"
            print(output_line)
            report.write(output_line + "\n")

    print("\n✅ Scan complete. Report saved to scan_report.txt")

if __name__ == "__main__":
    main()