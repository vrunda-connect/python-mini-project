# Phishing Link and Scam Message Checker
# Beginner project using Python Labs 1-7
# Lab 1: input/output, variables | Lab 2: operators, if/elif/else
# Lab 3: loops | Lab 4: strings | Lab 5: list, tuple, dictionary
# Lab 6: functions | Lab 7: file handling

# ---------- Lab 5: data (list, tuple, dictionary) ----------
SUSPICIOUS_WORDS = ["login", "verify", "update", "secure", "account",
                    "bank", "free", "bonus", "gift", "password", "kyc"]
SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "rb.gy")
BAD_ENDINGS = (".xyz", ".top", ".tk", ".click", ".work", ".ru", ".cf")

# phrase -> points (dictionary)
SCAM_PHRASES = {
    "urgent": 2,
    "act now": 2,
    "account blocked": 3,
    "account suspended": 3,
    "verify your": 2,
    "click here": 2,
    "you have won": 3,
    "lottery": 3,
    "prize": 2,
    "otp": 3,
    "share your pin": 4,
    "kyc": 2,
    "refund": 1,
    "limited time": 1,
    "send money": 3,
    "gift card": 3,
}

HISTORY_FILE = "history.txt"


# ---------- Lab 6: functions ----------
def get_host(url):
    """Return only the website name from a link."""
    url = url.lower().strip()
    if "://" in url:
        url = url.split("://")[1]          # Lab 4: string methods
    host = url.split("/")[0]
    return host


def check_link(url):
    """Return (score, reasons) for a link."""
    score = 0
    reasons = []
    url = url.lower().strip()
    host = get_host(url)

    # Lab 2: conditions
    if not url.startswith("https://"):
        score += 2
        reasons.append("Link does not use https")

    if "@" in url:
        score += 3
        reasons.append("Contains '@' symbol (can hide real site)")

    if host.replace(".", "").replace(":", "").isdigit():
        score += 3
        reasons.append("Uses an IP address instead of a website name")

    if len(url) > 75:
        score += 1
        reasons.append("Link is very long")

    if host.count("-") >= 2:
        score += 2
        reasons.append("Too many hyphens in the website name")

    if host.count(".") >= 4:
        score += 2
        reasons.append("Too many sub-domains")

    for s in SHORTENERS:                    # Lab 3: loop
        if s in host:
            score += 2
            reasons.append("Shortened link (real destination hidden)")
            break

    if host.endswith(BAD_ENDINGS):
        score += 2
        reasons.append("Uncommon domain ending often used in scams")

    for word in SUSPICIOUS_WORDS:
        if word in url:
            score += 1
            reasons.append("Suspicious word found: " + word)

    return score, reasons


def check_message(text):
    """Return (score, reasons) for a message."""
    score = 0
    reasons = []
    text = text.lower()

    for phrase, points in SCAM_PHRASES.items():
        if phrase in text:
            score += points
            reasons.append("Scam phrase: '" + phrase + "'")

    if text.count("!") >= 3:
        score += 1
        reasons.append("Too many exclamation marks")

    if "http" in text or "www." in text:
        score += 1
        reasons.append("Message contains a link")

    return score, reasons


def get_verdict(score):
    if score >= 6:
        return "HIGH RISK - Likely a scam. Do NOT click or reply."
    elif score >= 3:
        return "MEDIUM RISK - Looks suspicious. Be careful."
    else:
        return "LOW RISK - Seems okay, but stay alert."


def show_result(score, reasons):
    print("\nRisk score:", score)
    if len(reasons) == 0:
        print("No warning signs found.")
    else:
        print("Warning signs:")
        for r in reasons:
            print(" -", r)
    verdict = get_verdict(score)
    print("Verdict:", verdict)
    return verdict


# ---------- Lab 7: file handling ----------
def save_history(kind, text, score, verdict):
    f = open(HISTORY_FILE, "a")
    f.write(kind + " | " + text + " | score=" + str(score) + " | " + verdict + "\n")
    f.close()


def show_history():
    try:
        f = open(HISTORY_FILE, "r")
        lines = f.readlines()
        f.close()
        if len(lines) == 0:
            print("No history yet.")
        for line in lines:
            print(line.strip())
    except FileNotFoundError:
        print("No history yet.")


# ---------- Lab 1: main menu ----------
def main():
    print("=== Phishing Link & Scam Message Checker ===")
    while True:
        print("\n1. Check a link")
        print("2. Check a message")
        print("3. View history")
        print("4. Exit")
        choice = input("Enter choice (1-4): ")

        if choice == "1":
            url = input("Paste the link: ")
            score, reasons = check_link(url)
            verdict = show_result(score, reasons)
            save_history("LINK", url, score, verdict)
        elif choice == "2":
            msg = input("Paste the message: ")
            score, reasons = check_message(msg)
            verdict = show_result(score, reasons)
            save_history("MESSAGE", msg, score, verdict)
        elif choice == "3":
            show_history()
        elif choice == "4":
            print("Stay safe online!")
            break
        else:
            print("Invalid choice, try again.")


main()