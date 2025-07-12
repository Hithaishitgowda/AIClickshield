
# AIClickShield 
An AI-Enhanced Hybrid System for Detecting Clickjacking Vulnerabilities and Malicious Web Behavior

AIClickShield is a research-grade toolkit that detects both **technical vulnerabilities** and **malicious behaviors** arising from **clickjacking attacks**. It combines:

- - Static header inspection (X-Frame-Options, CSP)
- - iframe embedding tests using SSIM
- - JavaScript and framebusting detection
- - Behavioral simulation using Playwright
- - Visual intent analysis using OpenAI CLIP

---

## - Folder Structure

```bash
AIClickShield/
├── app.py                      # Flask backend
├── templates/index.html        # Web UI
├── static/                     # CSS/JS assets (optional)
├── ai/clip_analysis.py         # CLIP-based screenshot analysis
├── browser_sim/playwright_simulation.py  # Headless browser behavior scanner
├── vulndetect/                 # Header & iframe checkers
├── utils/ssim_compare.py       # Image similarity comparison
├── baseline_blocked.png        # Reference image for iframe-blocked pages
├── requirements.txt            # Python dependencies
└── .env                        # API keys (optional)
```

---

## - Requirements

- OS: Linux / macOS / Windows (WSL recommended for Windows)
- Python: 3.8 or later
- RAM: 8 GB+
- Disk: 5 GB+ free space
- Internet: Required for OpenAI CLIP (unless you use a local model)

---

## - Installation

### 1. Clone the repo

```bash
git clone https://github.com/your-username/AIClickShield.git
cd AIClickShield
```

### 2. Set up virtual environment

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
```

### 3. Install dependencies


```bash
pip install flask requests numpy pillow scikit-image playwright openai python-dotenv
```

### 4. Install Playwright browsers

```bash
playwright install
```

---

## - ChromeDriver (if needed)

For **Chrome-based automation** (for local tests or iframe rendering), make sure you install and configure `chromedriver`.

### Step-by-step:
1. Download from: https://chromedriver.chromium.org/downloads
2. Match the version with your Chrome browser.
3. Place it inside the project or any known directory.

### Update your script:
In any file using `chromedriver` (if applicable):

```python
from selenium import webdriver

driver = webdriver.Chrome(executable_path="/path/to/chromedriver")  # ⬅️ Update this path
```

---
## CLIP model setup


pip install torch torchvision
pip install git+https://github.com/openai/CLIP.git

---

## - Running the App

```bash
python app.py
```

Access the app in browser at:  
`http://127.0.0.1:5000`

---

## - Features

### - Static Vulnerability Detection

- Header checks (`X-Frame-Options`, `Content-Security-Policy`)
- iframe embedding test (compares with `baseline_blocked.png`)
- JavaScript/framebusting presence
- Rule-based scoring (0–100)

### - Behavioral Trap Detection

- Uses Playwright to simulate:
  - Scroll, click, double-click
  - DOM change detection
  - CSS traps: overlay, fake cursors, invisible iframes, etc.

### - Visual AI Detection

- Screenshot → CLIP (Image + Text AI model)
- Evaluates for misleading UI cues, overlays
- Outputs: Safe, Suspicious, Malicious

---

## - Example Output

```text
URL: https://example.com
Vulnerability Score: 75/100
Malicious Verdict: Suspicious
Details:
  - Headers Missing
  - Page can be embedded
  - Overlay trap detected
  - CLIP match: “Invisible overlay on button”
```

---

## - Note: baseline_blocked.png

This is a reference image (usually a "blocked iframe" default page). If missing:

1. Try embedding `https://google.com` in an iframe
2. Take a screenshot of how the browser blocks it
3. Save it as `baseline_blocked.png` in the root folder

---

## - Optional Dependencies

```bash
pip install opencv-python matplotlib shap
```

- For advanced screenshot analysis or visualization

---

## - Accuracy

| Module             | Accuracy     |
|--------------------|--------------|
| Behavioral Simulator | 93.3%        |
| CLIP Visual Model    | 83.3%        |
| Combined Verdict     | **90.0%**    |

---

## - Based on Research Paper

This implementation is derived from the IEEE-formatted paper:

**"AIClickShield: An AI-Enhanced Hybrid System for Clickjacking Detection"**  
Authors: Hithaishi Gowda, Sripriya Srinivas, Prof. Sushma E.  
Affiliation: PES University, Bengaluru, India

---

## - Future Enhancements (Suggested)

- Dockerize the setup
- Add batch URL scanning
- Convert it into a browser extension
- Cross-browser testing support (Firefox, Safari via Playwright)
- Mobile iframe clickjacking detection (Android webviews)

---

## - License

For research and educational use. Cite the paper if used in academic or industry projects.
