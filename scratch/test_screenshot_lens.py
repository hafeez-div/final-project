import io
import json
import urllib.request
import urllib.parse
from pathlib import Path
from PIL import Image
from dotenv import load_dotenv
import os
import sys

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

load_dotenv(Path(".env"))
api_key = os.environ.get("SERPAPI_API_KEY")
print("API key available:", bool(api_key))

p = Path(".digitalshield_data/cases/DS-2026-000010/evidence/EVD-2026-000010_Screenshot 2026-11-01 173824.png")
with open(p, "rb") as f:
    raw = f.read()

print("Original file size:", len(raw), "bytes")

# Optimize to under 500KB
with Image.open(io.BytesIO(raw)) as img:
    rgb = img.convert("RGB")
    buf = io.BytesIO()
    rgb.save(buf, format="JPEG", quality=85, optimize=True)
    optimized = buf.getvalue()

print("Optimized payload size:", len(optimized), "bytes (under 500KB:", len(optimized) < 500*1024, ")")

# Step 1: Upload to SerpApi
boundary = "----DigitalShieldBoundary7MA4YWxkTrZu0gW"
body = io.BytesIO()
body.write(f"--{boundary}\r\n".encode("utf-8"))
body.write(b'Content-Disposition: form-data; name="image"; filename="image.jpg"\r\n')
body.write(b"Content-Type: image/jpeg\r\n\r\n")
body.write(optimized)
body.write(b"\r\n")
body.write(f"--{boundary}\r\n".encode("utf-8"))
body.write(b'Content-Disposition: form-data; name="api_key"\r\n\r\n')
body.write(str(api_key).encode("utf-8"))
body.write(b"\r\n")
body.write(f"--{boundary}--\r\n".encode("utf-8"))

req = urllib.request.Request(
    "https://serpapi.com/image",
    data=body.getvalue(),
    headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
    method="POST"
)

with urllib.request.urlopen(req, timeout=30) as resp:
    data = json.loads(resp.read().decode("utf-8"))
    image_id = data.get("image_id")
    print("Step 1 Upload Success! HTTP 200. Image ID:", image_id)

# Step 2: Search Google Lens
params = urllib.parse.urlencode({
    "engine": "google_lens",
    "image_id": image_id,
    "api_key": api_key,
    "hl": "en",
    "type": "visual_matches",
})
search_url = f"https://serpapi.com/search?{params}"
with urllib.request.urlopen(urllib.request.Request(search_url), timeout=30) as resp:
    res = json.loads(resp.read().decode("utf-8"))
    vmatches = res.get("visual_matches", [])
    print(f"Step 2 Search Success! Visual Matches returned: {len(vmatches)}")
    print(f"Top 15 Visual Matches:")
    for i, vm in enumerate(vmatches[:15]):
        print(f"  [{i+1}] Source: {vm.get('source')} | Title: {vm.get('title')}")
        print(f"      Link: {vm.get('link')}")

    # Check for Instagram links
    ig_matches = [vm for vm in vmatches if "instagram.com" in (vm.get("link") or "").lower()]
    print(f"\nInstagram matches count: {len(ig_matches)}")
    for ig in ig_matches:
        print(f"  Instagram URL: {ig.get('link')} | Title: {ig.get('title')}")
