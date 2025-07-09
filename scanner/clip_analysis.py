import torch
import clip
from PIL import Image
import numpy as np
import csv
from io import BytesIO
from playwright.sync_api import sync_playwright

SAFE_OVERLAY_KEYWORDS = [
    "cookie", "consent", "close", "login", "signup", "modal", "dialog", "notification", "tooltip", "dropdown"
]

def is_known_safe_overlay_text(text):
    text = text.lower()
    return any(keyword in text for keyword in SAFE_OVERLAY_KEYWORDS)

class RobustClickjackDetector:
    def __init__(self):
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.model, self.preprocess = clip.load("ViT-B/32", device=self.device)
        self.safe_overlays = [
            "cookie consent banner with visible buttons",
            "login modal dialog",
            "signup modal dialog",
            "notification popup with close button",
            "help tooltip",
            "dropdown menu",
            "a normal web page with no overlays",
            "a web page with a visible and clickable button",
            "a web page with a legitimate modal dialog",
            "a web page with a visible close button on overlay",
            "a web page with a visible consent or privacy banner"
        ]
        self.malicious_overlays = [
            "completely transparent overlay with no visible close button",
            "semi-transparent layer covering interactive elements",
            "invisible iframe positioned over buttons",
            "UI element mimicking real buttons but performing hidden actions",
            "fake system alert or update prompt",
            "disguised element matching page style but with malicious intent",
            "a web page with a transparent div covering a button",
            "a web page with a hidden button",
            "a web page with a fake button",
            "a web page with a transparent overlay intercepting clicks",
            "a web page with a hidden overlay blocking user actions",
            "a web page with a disguised overlay that looks like the background"
        ]
        self.categories = self.safe_overlays + self.malicious_overlays

    def analyze_element(self, pil_image):
        clip_result = self._clip_overlay_verdict(pil_image)
        return clip_result

    def _clip_overlay_verdict(self, image):
        image_input = self.preprocess(image).unsqueeze(0).to(self.device)
        text_inputs = clip.tokenize(self.categories).to(self.device)
        with torch.no_grad():
            image_features = self.model.encode_image(image_input)
            text_features = self.model.encode_text(text_inputs)
            logits = (image_features @ text_features.T) * self.model.logit_scale.exp()
            probs = logits.softmax(dim=-1).cpu().numpy()[0]
        top_match_idx = int(np.argmax(probs))
        top_category = self.categories[top_match_idx]
        top_prob = float(probs[top_match_idx])

        explanation = ""
        if top_category in self.safe_overlays or is_known_safe_overlay_text(top_category):
            verdict = "safe"
            explanation = (
                f"The screenshot most closely matches a safe overlay or normal UI pattern: '{top_category}'.\n"
                "Detected overlay is considered legitimate (cookie banner, login/signup modal, notification, tooltip, dropdown, or visible close/consent button), "
                "or the page has no suspicious overlays."
            )
        elif top_category in self.malicious_overlays:
            verdict = "malicious"
            explanation = (
                f"The screenshot most closely matches a known malicious overlay pattern: '{top_category}'.\n"
                "Detected overlay is not a standard UI element and may be hiding or intercepting user actions."
            )
        else:
            verdict = "suspicious"
            explanation = (
                f"The screenshot does not clearly match a safe or malicious overlay pattern. Top match: '{top_category}'.\n"
                "Manual review recommended."
            )

        return {
            "verdict": verdict,
            "confidence": int(top_prob * 100),
            "explanation": explanation,
            "top_match": top_category
        }

"""def clip_visual_risk(pil_image):
    analyzer = RobustClickjackDetector()
    result = analyzer.analyze_element(pil_image)
    clip_details = result["explanation"]
    return result["verdict"], result["confidence"], clip_details

def update_ground_truth_with_clip(csv_path):
    updated_rows = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--disable-http2"])
        page = browser.new_page(ignore_https_errors=True)

        with open(csv_path, mode='r', newline='', encoding='utf-8') as infile:
            reader = csv.reader(infile)
            headers = next(reader)

            if len(headers) < 4:
                headers.append("clip_verdict")
            updated_rows.append(headers)

            for row in reader:
                url = row[0]
                print(f"Processing: {url}")

                try:
                    page.goto(url, timeout=15000, wait_until="domcontentloaded")
                    img_bytes = page.screenshot(full_page=True)
                    pil_image = Image.open(BytesIO(img_bytes)).convert("RGB")

                    verdict, confidence, explanation = clip_visual_risk(pil_image)

                    # ✅ Print full explanation and confidence
                    print(f"[{url}] Verdict: {verdict.upper()} ({confidence}%)")
                    print(f"Explanation: {explanation}\n")

                except Exception as e:
                    verdict = "clip_error"
                    print(f"[ERROR] {url}: {e.__class__.__name__} - {e}")

                if len(row) < 4:
                    row.append(verdict)
                else:
                    row[3] = verdict

                updated_rows.append(row)

        browser.close()

    with open(csv_path, mode='w', newline='', encoding='utf-8') as outfile:
        writer = csv.writer(outfile)
        writer.writerows(updated_rows)

if __name__ == "__main__":
    update_ground_truth_with_clip("ground_truth.csv")"""
