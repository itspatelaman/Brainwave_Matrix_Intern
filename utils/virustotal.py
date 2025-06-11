import requests

API_KEY = "enter_your_api_key"  # Replace with your VirusTotal API key
VT_URL = "https://www.virustotal.com/api/v3/urls"

def check_url_virustotal(url):
    try:
        scan_url = f"https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": API_KEY}
        
        # 1. Submit the URL for analysis (encode it first)
        response = requests.post(scan_url, headers=headers, data={"url": url})
        if response.status_code != 200:
            return "VT: Submission failed"
        
        analysis_id = response.json()["data"]["id"]

        # 2. Retrieve the report
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report_resp = requests.get(report_url, headers=headers)
        if report_resp.status_code != 200:
            return "VT: Report fetch failed"

        stats = report_resp.json()["data"]["attributes"]["stats"]
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0 or suspicious > 0:
            return f"VT: 🚨 Malicious ({malicious} engines)"
        else:
            return "VT: ✅ Clean"

    except Exception as e:
        return "VT: Error fetching results"
