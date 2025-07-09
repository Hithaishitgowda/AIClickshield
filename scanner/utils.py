import os
import json
import random
import time
from PIL import Image
import numpy as np
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from webdriver_manager.chrome import ChromeDriverManager
from skimage.metrics import structural_similarity as ssim

PATTERN_DB = os.path.join(os.path.dirname(__file__), "suspicious_patterns.json")

WINDOW_WIDTH = 1024
WINDOW_HEIGHT = 768
SCREENSHOT_DIR = "static/screenshots"
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

CHROMEDRIVER_PATH = "/Users/hithaishigowda/Downloads/chromedriver-mac-arm64/chromedriver"  # <--- PUT YOUR CHROMEDRIVER PATH HERE

def ensure_url_scheme(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        return "http://" + url
    return url

def load_patterns():
    if not os.path.exists(PATTERN_DB):
        with open(PATTERN_DB, "w") as f:
            json.dump([], f)
    with open(PATTERN_DB, "r") as f:
        return json.load(f)

def save_patterns(patterns):
    with open(PATTERN_DB, "w") as f:
        json.dump(patterns, f, indent=2)

def simulate_human_actions_and_detect_traps(url):
    url = ensure_url_scheme(url)
    options = Options()
    options.headless = True
    driver = webdriver.Chrome(service=Service(CHROMEDRIVER_PATH), options=options)
    actions_log = []
    traps_found = []
    try:
        driver.get(url)
        time.sleep(random.uniform(1, 2))

        # Capture overlays before interaction
        overlays_before = set()
        viewport_area = WINDOW_WIDTH * WINDOW_HEIGHT
        elements = driver.find_elements(By.XPATH, "//*")
        for ov in elements:
            try:
                size = ov.size
                area = size['width'] * size['height']
                if area < 0.5 * viewport_area:
                    continue
                opacity = float(ov.value_of_css_property('opacity') or 1.0)
                if opacity > 0.2:
                    continue
                zindex = ov.value_of_css_property('z-index')
                zindex_val = int(zindex) if zindex and zindex != 'auto' else 0
                if zindex_val < 1000:
                    continue
                overlays_before.add(ov)
            except Exception:
                continue

        # Simulate user actions
        for i in range(3):
            driver.execute_script("window.scrollBy(0, window.innerHeight/2);")
            actions_log.append(f"Scrolled down ({i+1})")
            time.sleep(random.uniform(0.5, 1.2))

        clickable = driver.find_elements(By.XPATH, "//a | //button | //*[@onclick]")
        for elem in clickable[:3]:
            try:
                driver.execute_script("arguments[0].scrollIntoView();", elem)
                elem.click()
                actions_log.append(f"Clicked element: {elem.tag_name}")
                time.sleep(random.uniform(0.5, 1.2))
            except Exception:
                continue

        # Capture overlays after interaction
        overlays_after = []
        elements = driver.find_elements(By.XPATH, "//*")
        for ov in elements:
            try:
                size = ov.size
                area = size['width'] * size['height']
                if area < 0.5 * viewport_area:
                    continue
                opacity = float(ov.value_of_css_property('opacity') or 1.0)
                if opacity > 0.2:
                    continue
                zindex = ov.value_of_css_property('z-index')
                zindex_val = int(zindex) if zindex and zindex != 'auto' else 0
                if zindex_val < 1000:
                    continue
                if ov not in overlays_before:
                    overlays_after.append(ov)
            except Exception:
                continue

        # Only flag overlays that appeared after interaction
        for ov in overlays_after:
            traps_found.append({
                "type": "Overlay Div",
                "description": "Large transparent overlay div detected after interaction.",
                "details": f"Tag: {ov.tag_name}, id: {ov.get_attribute('id')}, opacity: {ov.value_of_css_property('opacity')}, pointer-events: {ov.value_of_css_property('pointer-events')}, z-index: {ov.value_of_css_property('z-index')}"
            })

        shap_explanation = []
        if traps_found:
            shap_explanation.append("Large, low-opacity, high-z-index overlays appeared after interaction (strict clickjacking indicator)")

        behavioral_verdict = "malicious" if traps_found else "safe"
        return {
            "actions_log": actions_log,
            "traps_found": traps_found,
            "shap_explanation": shap_explanation,
            "risk_score": min(100, 40*len(traps_found)),
            "behavioral_verdict": behavioral_verdict
        }
    finally:
        driver.quit()

def check_headers(url):
    import requests
    url = ensure_url_scheme(url)
    try:
        resp = requests.get(url, timeout=5)
        headers = resp.headers
        xfo = headers.get("X-Frame-Options", "Missing")
        csp = headers.get("Content-Security-Policy", "Missing")
        return {
            "status": "ok",
            "reason": "Headers checked.",
            "headers": {
                "X-Frame-Options": xfo,
                "Content-Security-Policy": csp
            }
        }
    except Exception as e:
        return {
            "status": "error",
            "reason": str(e),
            "headers": {
                "X-Frame-Options": "Unknown",
                "Content-Security-Policy": "Unknown"
            }
        }

def calculate_ssim(img1_path, img2_path, threshold=0.90):
    try:
        img1 = Image.open(img1_path).convert("L")
        img2 = Image.open(img2_path).convert("L")
    except Exception:
        return False

    if img1.size != img2.size:
        img2 = img2.resize(img1.size)

    img1_np = np.array(img1)
    img2_np = np.array(img2)

    score, _ = ssim(img1_np, img2_np, full=True)
    print("SSIM score for iframe embedding:", score)
    return bool(score < threshold)

def can_be_embedded(url):
    chrome_options = Options()
    chrome_options.add_argument("--headless=new")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument(f"--window-size={WINDOW_WIDTH},{WINDOW_HEIGHT}")
    driver = webdriver.Chrome(service=Service(CHROMEDRIVER_PATH), options=chrome_options)

    try:
        html_content = f"""
        <html>
        <body>
            <iframe src="{url}" width="{WINDOW_WIDTH}" height="{WINDOW_HEIGHT}" style="border: none;"></iframe>
        </body>
        </html>
        """
        test_file = "test_iframe.html"
        with open(test_file, "w") as f:
            f.write(html_content)

        local_file = "file://" + os.path.abspath(test_file)
        driver.get(local_file)
        time.sleep(3)
        try:
            iframe = driver.find_element(By.TAG_NAME, "iframe")
            driver.switch_to.frame(iframe)
            body_text = driver.find_element(By.TAG_NAME, "body").text.lower()
            # Check for common browser error messages
            if (
                "refused to connect" in body_text
                or "not allowed" in body_text
                or "blocked" in body_text
                or "error" in body_text
                or body_text.strip() == ""
            ):
                embeddable = False
            else:
                embeddable = True
        except Exception:
            embeddable = False

        screenshot_filename = f"screenshots/iframe_{int(time.time())}.png"
        screenshot_path = os.path.join(os.path.dirname(__file__), "../static", screenshot_filename)
        driver.save_screenshot(screenshot_path)

        if embeddable:
            return True, screenshot_filename
        else:
            if os.path.exists(screenshot_path):
                os.remove(screenshot_path)
            return False, None

    except Exception:
        return False, None
    finally:
        driver.quit()
        if os.path.exists("test_iframe.html"):
            os.remove("test_iframe.html")

def is_javascript_enabled(url):
    url = ensure_url_scheme(url)
    options = Options()
    options.headless = True
    driver = webdriver.Chrome(options=options)
    try:
        driver.get(url)
        time.sleep(1)
        driver.execute_script("window.testVar = 123;")
        val = driver.execute_script("return window.testVar;")
        return val == 123
    except Exception:
        return False
    finally:
        driver.quit()

def capture_realpage_screenshot(url):
    url = ensure_url_scheme(url)
    options = Options()
    options.headless = True
    driver = webdriver.Chrome(options=options)
    try:
        driver.get(url)
        driver.set_window_size(1200, 900)
        time.sleep(2)
        # Ensure the screenshots directory exists
        screenshots_dir = os.path.join(os.path.dirname(__file__), "../static/screenshots")
        os.makedirs(screenshots_dir, exist_ok=True)
        screenshot_path = os.path.join(screenshots_dir, "realpage.png")
        driver.save_screenshot(screenshot_path)
        img = Image.open(screenshot_path)
        return img, "screenshots/realpage.png"
    finally:
        driver.quit()


