import time
import urllib.request
import json
from pathlib import Path

url = "https://aegis-backend-oybm.onrender.com/api/v1/health"
print(f"Pinging live backend: {url} ...")
t0 = time.time()
try:
    req = urllib.request.Request(url, headers={"User-Agent": "Aegis-Health-Monitor/1.0"})
    with urllib.request.urlopen(req, timeout=90) as resp:
        elapsed = (time.time() - t0) * 1000
        code = resp.status
        body = resp.read().decode("utf-8")
        print(f"Response received in {elapsed:.1f} ms (HTTP {code}):")
        print(body)
        res = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "url": url,
            "status_code": code,
            "latency_ms": round(elapsed, 1),
            "response": json.loads(body) if body.startswith("{") else body
        }
        Path("evidences/06_live_health_ping.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
        print("Logged to evidences/06_live_health_ping.json")
except Exception as e:
    elapsed = (time.time() - t0) * 1000
    print(f"Error after {elapsed:.1f} ms: {e}")
    res = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "url": url,
        "error": str(e),
        "latency_ms": round(elapsed, 1)
    }
    Path("evidences/06_live_health_ping.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
