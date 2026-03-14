import math
import re

COMMON_PATTERNS = {
    "password", "123456", "qwerty", "admin", "letmein", "welcome",
    "abc123", "111111", "iloveyou", "user", "login", "tanmoy"
}

SPECIAL_CHARACTERS = "!@#$%^&*()_+-=[]{}|;:',.<>?/`~"


def calculate_charset_size(password):
    charset = 0

    if any(char.islower() for char in password):
        charset += 26
    if any(char.isupper() for char in password):
        charset += 26
    if any(char.isdigit() for char in password):
        charset += 10
    if any(char in SPECIAL_CHARACTERS for char in password):
        charset += len(SPECIAL_CHARACTERS)

    return charset


def calculate_entropy(password):
    charset_size = calculate_charset_size(password)
    if charset_size == 0:
        return 0
    return len(password) * math.log2(charset_size)


def check_common_patterns(password):
    lower_password = password.lower()

    if lower_password in COMMON_PATTERNS:
        return True

    for pattern in COMMON_PATTERNS:
        if pattern in lower_password:
            return True

    if re.search(r"(.)\1\1", password):
        return True

    return False


def analyze_password(password):
    issues = []
    suggestions = []
    score = 0

    length = len(password)

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in SPECIAL_CHARACTERS for c in password)

    if length >= 12:
        score += 2
    elif length >= 8:
        score += 1
    else:
        issues.append("Password is too short.")
        suggestions.append("Use at least 12 characters.")

    if has_lower:
        score += 1
    else:
        issues.append("Add lowercase letters.")

    if has_upper:
        score += 1
    else:
        issues.append("Add uppercase letters.")

    if has_digit:
        score += 1
    else:
        issues.append("Add numbers.")

    if has_special:
        score += 1
    else:
        issues.append("Add special characters.")

    if check_common_patterns(password):
        issues.append("Password contains common patterns.")
        suggestions.append("Avoid common words or patterns.")
        score -= 1

    entropy = calculate_entropy(password)

    if score <= 1:
        strength = "Very Weak"
    elif score == 2:
        strength = "Weak"
    elif score == 3:
        strength = "Moderate"
    elif score in (4, 5):
        strength = "Strong"
    else:
        strength = "Very Strong"

    return strength, round(entropy, 2), issues, suggestions


def main():
    print("Cybersecurity Password Strength Checker")
    print("---------------------------------------")

    password = input("Enter a password to analyze: ")

    strength, entropy, issues, suggestions = analyze_password(password)

    print("\nResult")
    print("------")
    print("Strength:", strength)
    print("Entropy:", entropy, "bits")

    if issues:
        print("\nIssues:")
        for i in issues:
            print("-", i)

    if suggestions:
        print("\nSuggestions:")
        for s in suggestions:
            print("-", s)


if __name__ == "__main__":
    main()
