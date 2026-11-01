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

p = Path(".digitalshield_data/cases/DS-2026-000010/evidence/EVD-2026-000010_Screenshot 2026-11-01 173824.png")
original_img = Image.open(p)
w, h = original_img.size

crops = {
    "Full Screenshot": original_img,
    "Middle Photo Crop": original_img.crop((10, 80, w - 10, h - 80)),
    "Center Subject Crop": original_img.crop((30, 120, w - 30, h - 140)),
}

def search_image(label, img_obj):
    print(f"\n==========================================")
    print(f"SEARCHING: {label} (Dimensions: {img_obj.size})")
    print(f"==========================================")
    
    rgb = img_obj.convert("RGB")
    buf = io.BytesIO()
    rgb.save(buf, format="JPEG", quality=85, optimize=True)
    payload = buf.getvalue()
    print(f"Payload size: {len(payload)} bytes (under 500KB: {len(payload) < 500*1024})")

    boundary = "----DigitalShieldBoundary7MA4YWxkTrZu0gW"
    body = io.BytesIO()
    body.write(f"--{boundary}\r\n".encode("utf-8"))
    body.write(b'Content-Disposition: form-data; name="image"; filename="image.jpg"\r\n')
    body.write(b"Content-Type: image/jpeg\r\n\r\n")
    body.write(payload)
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
        print(f"Upload Success! Image ID: {image_id[:20]}...")

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
        print(f"Total Visual Matches returned: {len(vmatches)}")

    urls = [vm.get("link") for vm in vmatches if vm.get("link")]
    titles = [vm.get("title") for vm in vmatches]
    ig_urls = [u for u in urls if "instagram.com" in u.lower()]
    print(f"Instagram URLs returned: {len(ig_urls)}")
    for i, (u, t) in enumerate(zip(urls[:8], titles[:8])):
        print(f"  [{i+1}] {t[:50]} -> {u}")

    return {
        "label": label,
        "total": len(vmatches),
        "ig_count": len(ig_urls),
        "urls": urls,
        "matches": vmatches
    }

results = {}
for name, img in crops.items():
    results[name] = search_image(name, img)

print("\n\n==========================================")
print("COMPARISON SUMMARY")
print("==========================================")
for name, r in results.items():
    print(f"{name}: Total {r['total']} matches, {r['ig_count']} Instagram links")

# Check overlap between crops
full_urls = set(results["Full Screenshot"]["urls"])
mid_urls = set(results["Middle Photo Crop"]["urls"])
center_urls = set(results["Center Subject Crop"]["urls"])

print(f"\nUnique URLs across all 3 queries: {len(full_urls | mid_urls | center_urls)}")
print(f"Overlap between Full and Middle: {len(full_urls & mid_urls)}")
print(f"Overlap between Middle and Center: {len(mid_urls & center_urls)}")

# Check if any URL is an exact post URL
print("\nExamining candidate post URLs for exact match...")
for name, r in results.items():
    print(f"\nTop 5 for {name}:")
    for vm in r["matches"][:5]:
        print(f"  Title: {vm.get('title')}")
        print(f"  Link:  {vm.get('link')}")
        print(f"  Thumbnail: {vm.get('thumbnail')}")
