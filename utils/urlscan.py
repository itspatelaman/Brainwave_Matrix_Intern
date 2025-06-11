import requests
import time

API_KEY = "enter_your_api_key"  # Replace with your key
HEADERS = {"API-Key": API_KEY, "Content-Type": "application/json"}

def scan_url_with_urlscan(url):
    try:
        submission = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=HEADERS,
            json={"url": url, "visibility": "public"}
        )

        if submission.status_code != 200:
            return {"status": "error", "message": submission.text}

        scan_id = submission.json()["uuid"]
        result_url = f"https://urlscan.io/api/v1/result/{scan_id}/"

        # Wait a few seconds before fetching result
        time.sleep(10)
        result = requests.get(result_url)

        if result.status_code == 200:
            data = result.json()
            return {
                "result_link": f"https://urlscan.io/result/{scan_id}/",
                "domain": data.get("page", {}).get("domain", "Unknown"),
                "ip": data.get("page", {}).get("ip", "Unknown"),
                "country": data.get("page", {}).get("country", "Unknown"),
                "server": data.get("page", {}).get("server", "Unknown"),
                "tags": data.get("verdicts", {}).get("overall", {}).get("tags", []),
            }
        else:
            return {"status": "error", "message": "Result fetch failed."}

    except Exception as e:
        return {"status": "error", "message": str(e)}
