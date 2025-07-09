import csv
from collections import defaultdict

# Structures to store data
suspicious_ips = defaultdict(int)        # Basic count-based
url_feedback = defaultdict(list)         # For group analysis
ip_scores = defaultdict(int)             # Behavior + collusion scoring

with open('user_feedback.csv', 'r') as f:
    reader = csv.reader(f)
    headers = next(reader, None)  # skip header row if present

    for row in reader:
        if len(row) < 6:
            continue

        url = row[0].strip()
        real_verdict = row[1].strip().lower()
        agree = row[2].strip().lower()
        user_verdict = row[3].strip().lower()
        ip = row[5].strip()

        # --- BASIC: Suspicious if disagreed with risky verdict and marked it safe ---
        if real_verdict in ['malicious', 'suspicious'] and agree == 'no' and user_verdict == 'safe':
            suspicious_ips[ip] += 1  # Count-based suspicion
            ip_scores[ip] += 5       # Score-based suspicion
            url_feedback[url].append((agree, user_verdict, ip, real_verdict))

# --- ADVANCED: Group-level collusion penalty ---
for url, feedbacks in url_feedback.items():
    disagreeing_ips = [
        ip for agree, user_verdict, ip, real_verdict in feedbacks
        if real_verdict in ['malicious', 'suspicious'] and agree == 'no' and user_verdict == 'safe'
    ]

    if len(disagreeing_ips) >= 3:
        for ip in disagreeing_ips:
            ip_scores[ip] += 10  # Group collusion penalty

# --- RESULTS ---
print("\n🚨 Basic Suspicious IPs (disagreed more than once):")
for ip, count in suspicious_ips.items():
    if count >= 2:
        print(f"⚠️ {ip} marked malicious/suspicious sites as safe {count} times")

print("\n🚨 Behavior-Based Suspicion Scores:")
for ip, score in sorted(ip_scores.items(), key=lambda x: x[1], reverse=True):
    if score >= 2:
        print(f"⚠️ {ip} → Suspicion Score: {score}")
