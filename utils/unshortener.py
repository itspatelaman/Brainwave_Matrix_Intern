# utils/unshortener.py

import requests

def unshorten_url(url):
    try:
        response = requests.head(url, allow_redirects=True, timeout=5)
        return response.url
    except Exception as e:
        return f"[ERROR] Could not unshorten: {e}"
