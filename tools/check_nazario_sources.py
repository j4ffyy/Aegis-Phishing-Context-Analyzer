import urllib.request
import re
import hashlib
from pathlib import Path

def main():
    url = "https://monkey.org/~jose/phishing/"
    print(f"Connecting to canonical Nazario repository: {url}")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
            matches = sorted(list(set(re.findall(r'href="([^"]+\.mbox(?:\.bz2)?)', html))))
            print(f"Discovered {len(matches)} archives on monkey.org:")
            for m in matches[:15]:
                print(f"  - {m}")
    except Exception as e:
        print(f"Error accessing {url}: {e}")

if __name__ == "__main__":
    main()

