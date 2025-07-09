import os
import csv
from flask import Flask, render_template, request
from scanner.utils import (
    check_headers,
    can_be_embedded,
    is_javascript_enabled,
    ensure_url_scheme,
    capture_realpage_screenshot
)
from scanner.clip_analysis import RobustClickjackDetector
from scanner.playwright_simulation import human_like_browse

app = Flask(__name__, static_folder='../static')

# Store latest verdicts for feedback lookup
temp_verdicts = {}

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']
        url = ensure_url_scheme(url)

        # 1. Behavioral simulation (Playwright)
        behavior_result = human_like_browse(url)
        behavioral_verdict = behavior_result.get("behavioral_verdict", "safe").strip().lower()

        # 2. Security headers
        header_result = check_headers(url)
        xfo = header_result['headers']['X-Frame-Options']
        csp = header_result['headers']['Content-Security-Policy']

        # 3. Iframe embedding
        iframe_successful, iframe_screenshot = can_be_embedded(url)
        if not iframe_successful:
            iframe_screenshot = None

        # 4. JS enabled
        js_enabled = is_javascript_enabled(url)

        # 5. CLIP visual analysis
        real_img, real_filename = capture_realpage_screenshot(url)
        analyzer = RobustClickjackDetector()
        clip_result = analyzer.analyze_element(real_img)
        clip_verdict = clip_result["verdict"]
        clip_confidence = clip_result["confidence"]
        clip_details = clip_result["explanation"]
        clip_verdict = clip_verdict.strip().lower()

        # --- Technical risk scoring (only technical factors) ---
        technical_score = 0
        technical_reasons = []

        # --- X-Frame-Options scoring ---
        if xfo == 'Missing':
            technical_score += 30
            technical_reasons.append("X-Frame-Options header is missing (high risk).")
        elif xfo.upper() == 'DENY':
            technical_score += 0
            technical_reasons.append("X-Frame-Options is DENY (best protection).")
        elif xfo.upper() == 'SAMEORIGIN':
            technical_score += 5
            technical_reasons.append("X-Frame-Options is SAMEORIGIN (good protection).")
        elif xfo.upper().startswith('ALLOW-FROM'):
            technical_score += 15
            technical_reasons.append("X-Frame-Options is ALLOW-FROM (weak, deprecated).")
        else:
            technical_score += 20
            technical_reasons.append(f"X-Frame-Options value '{xfo}' is unrecognized (potential risk).")

        # --- CSP scoring ---
        if csp == 'Missing':
            technical_score += 35
            technical_reasons.append("Content-Security-Policy header is missing (high risk).")
        elif "frame-ancestors" in csp.lower():
            import re
            match = re.search(r"frame-ancestors\s+([^;]+)", csp, re.IGNORECASE)
            if match:
                fa_value = match.group(1).strip().strip(";")
                if "'none'" in fa_value:
                    technical_score += 0
                    technical_reasons.append("CSP frame-ancestors 'none' (best protection).")
                elif "'self'" in fa_value:
                    technical_score += 5
                    technical_reasons.append("CSP frame-ancestors 'self' (good protection).")
                elif "*" in fa_value:
                    technical_score += 25
                    technical_reasons.append("CSP frame-ancestors * (allows all, weak).")
                else:
                    technical_score += 10
                    technical_reasons.append(f"CSP frame-ancestors {fa_value} (medium protection).")
            else:
                technical_score += 15
                technical_reasons.append("CSP header present but frame-ancestors directive not explicit (potential risk).")
        else:
            technical_score += 15
            technical_reasons.append("CSP header lacks frame-ancestors directive (potential risk).")

        if iframe_successful:
            technical_score += 25
            technical_reasons.append("Page can be embedded in an iframe (classic clickjacking risk).")

        if not js_enabled:
            technical_score += 10
            technical_reasons.append("JavaScript appears to be disabled or blocked.")

        technical_score = min(100, technical_score)

        # --- Overall result for the page (behavioral + AI only) ---
        if behavioral_verdict == "malicious":
            overall_result = "malicious"
        elif behavioral_verdict == "suspicious":
            overall_result = "suspicious"
        else:  # behavioral_verdict is "safe"
            if clip_verdict == "malicious":
                overall_result = "suspicious"
            elif clip_verdict == "suspicious":
                overall_result = "suspicious"
            else:  # clip_verdict is "safe"
                overall_result = "safe"

        # Store for feedback lookup
        temp_verdicts[url] = overall_result

        # --- Behavioral/AI explanations ---
        trap_type_map = {
            "Overlay Div": "UI Redressing (Overlay Clickjacking)",
            "Pointer Events": "UI Redressing (Pointer-events Clickjacking)",
            "Multi-step Trap": "Advanced Clickjacking (Multi-step interaction required)",
            "Animated Trap": "Advanced Clickjacking (Animated overlay or delayed trap)"
        }
        verdict_reasons = []
        for trap in behavior_result['traps_found']:
            if isinstance(trap, dict):
                trap_type = trap.get("type", "Unknown")
                trap_desc = trap.get("description", "")
                trap_details = trap.get("details", "")
                verdict_reasons.append(
                    f"Detected {trap_type_map.get(trap_type, trap_type)}: {trap_desc} {trap_details}"
                )
            else:
                verdict_reasons.append(trap)
        verdict_reasons.append("Behavioral SHAP-like explanation: " + ", ".join(behavior_result['shap_explanation']))
        verdict_reasons.append(f"CLIP AI verdict: {clip_verdict.upper()} ({clip_confidence}% confidence)")

        return render_template(
            'report.html',
            url=url,
            header_result=header_result,
            iframe_successful=iframe_successful,
            iframe_screenshot=iframe_screenshot,
            js_enabled=js_enabled,
            actions_log=behavior_result['actions_log'],
            traps_found=behavior_result['traps_found'],
            shap_explanation=behavior_result['shap_explanation'],
            technical_score=technical_score,
            technical_reasons=technical_reasons,
            overall_result=overall_result,
            verdict_reasons=verdict_reasons,
            clip_verdict=clip_verdict,
            clip_confidence=clip_confidence,
            real_screenshot=real_filename,
            behavioral_verdict=behavioral_verdict,
        )
    return render_template('index.html')

@app.route('/feedback', methods=['POST'])
def feedback():
    url = request.form.get('url')
    agree = request.form.get('agree')
    user_verdict = request.form.get('user_verdict')
    reason = request.form.get('reason')
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)

    # Use the latest overall result for this URL
    real_verdict = temp_verdicts.get(url, '')

    with open('user_feedback.csv', 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([url, real_verdict, agree, user_verdict, reason, ip])

    return '', 200

if __name__ == '__main__':
    app.run(debug=True,port=os.getenv('PORT', 5000))