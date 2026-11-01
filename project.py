
import argparse
import csv
import getpass
import math
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_COMMON_PASSWORDS = BASE_DIR / "data" / "common_passwords.txt"
DEFAULT_MIN_LENGTH = 12


def check_length(password, minimum=DEFAULT_MIN_LENGTH):
    if minimum < 1:
        raise ValueError("minimum must be at least 1")
    return len(password) >= minimum


def analyze_characters(password):
    counts = {
        "uppercase": 0,
        "lowercase": 0,
        "digits": 0,
        "symbols": 0,
        "whitespace": 0,
    }

    pool_size = 0

    if any(char.islower() for char in password):
        pool_size += 26
    if any(char.isupper() for char in password):
        pool_size += 26
    if any(char.isdigit() for char in password):
        pool_size += 10
    if any(not char.isalnum() and not char.isspace() for char in password):
        pool_size += 33
    if any(char.isspace() for char in password):
        pool_size += 1

    for char in password:
        if char.isupper():
            counts["uppercase"] += 1
        elif char.islower():
            counts["lowercase"] += 1
        elif char.isdigit():
            counts["digits"] += 1
        elif char.isspace():
            counts["whitespace"] += 1
        else:
            counts["symbols"] += 1

    counts["pool_size"] = pool_size
    return counts


def load_common_passwords(path=DEFAULT_COMMON_PASSWORDS):
    try:
        with Path(path).open(encoding="utf-8") as file:
            return {line.strip().casefold() for line in file if line.strip()}
    except FileNotFoundError:
        return set()


def check_common_password(password, common_passwords=None):
    if common_passwords is None:
        common_passwords = load_common_passwords()

    normalized = password.casefold()
    return normalized in {item.casefold() for item in common_passwords}


def estimate_entropy(password, character_analysis=None):
    if not password:
        return 0.0

    if character_analysis is None:
        character_analysis = analyze_characters(password)

    pool_size = character_analysis["pool_size"]

    if pool_size == 0:
        return 0.0

    return len(password) * math.log2(pool_size)


def evaluate_password(password, minimum=DEFAULT_MIN_LENGTH):
    characters = analyze_characters(password)
    common = check_common_password(password)
    entropy = estimate_entropy(password, characters)
    length_ok = check_length(password, minimum)

    score = 0

    if length_ok:
        score += 2
    if len(password) >= 16:
        score += 1

    score += sum(
        characters[key] > 0
        for key in ("uppercase", "lowercase", "digits", "symbols")
    )

    if entropy >= 60:
        score += 1

    if common:
        score = 0

    if common:
        strength = "Very weak"
    elif score <= 2:
        strength = "Weak"
    elif score <= 4:
        strength = "Moderate"
    elif score <= 5:
        strength = "Good"
    else:
        strength = "Strong"

    return {
        "length": len(password),
        "minimum_length": minimum,
        "length_ok": length_ok,
        "characters": characters,
        "common_password": common,
        "estimated_entropy_bits": round(entropy, 1),
        "score": score,
        "strength": strength,
        "recommendations": generate_recommendations(
            password, characters, common, length_ok, minimum
        ),
    }


def generate_recommendations(password, characters, common, length_ok, minimum):
    recommendations = []

    if not password:
        return ["Use a long, unique password or passphrase."]

    if common:
        recommendations.append(
            "This password appears in the common-password list; replace it."
        )

    if not length_ok:
        recommendations.append(
            f"Use at least {minimum} characters; a longer passphrase is preferable."
        )

    if characters["lowercase"] == 0 or characters["uppercase"] == 0:
        recommendations.append(
            "Consider using a randomly generated mix of upper- and lowercase letters."
        )

    if characters["digits"] == 0:
        recommendations.append(
            "Consider including digits in a randomly generated password."
        )

    if characters["symbols"] == 0:
        recommendations.append(
            "Consider including symbols if the service permits them."
        )

    if len(password) >= minimum and not recommendations:
        recommendations.append(
            "Use a unique password for every account and store it in a reputable password manager."
        )

    recommendations.append(
        "Prefer a randomly generated password or a long, random passphrase."
    )

    return recommendations


def write_report_csv(result, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    row = {
        "length": result["length"],
        "minimum_length": result["minimum_length"],
        "length_ok": result["length_ok"],
        "uppercase": result["characters"]["uppercase"],
        "lowercase": result["characters"]["lowercase"],
        "digits": result["characters"]["digits"],
        "symbols": result["characters"]["symbols"],
        "common_password": result["common_password"],
        "estimated_entropy_bits": result["estimated_entropy_bits"],
        "strength": result["strength"],
        "recommendations": " | ".join(result["recommendations"]),
    }

    with output_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=row.keys())
        writer.writeheader()
        writer.writerow(row)


def print_report(result):
    print("\n" + "=" * 48)
    print("             PASSWORD AUDIT REPORT")
    print("=" * 48)

    print(f"Length:                 {result['length']}")
    print(f"Minimum length met:     {'Yes' if result['length_ok'] else 'No'}")
    print(f"Uppercase characters:   {result['characters']['uppercase']}")
    print(f"Lowercase characters:   {result['characters']['lowercase']}")
    print(f"Digits:                 {result['characters']['digits']}")
    print(f"Symbols:                {result['characters']['symbols']}")
    print(f"Common-list match:      {'Yes' if result['common_password'] else 'No'}")
    print(f"Estimated entropy:      {result['estimated_entropy_bits']} bits")
    print(f"Assessment:             {result['strength']}")

    print("\nRecommendations:")

    for recommendation in result["recommendations"]:
        print(f"- {recommendation}")

    print("\nNote: This is an educational heuristic, not a guarantee of security.")
    print("=" * 48)


def main():
    parser = argparse.ArgumentParser(
        description="Audit a password locally without saving or transmitting it."
    )

    parser.add_argument(
        "--minimum-length",
        type=int,
        default=DEFAULT_MIN_LENGTH,
    )

    parser.add_argument(
        "--csv",
        metavar="PATH",
        help="Save a password-free CSV report",
    )

    args = parser.parse_args()

    if args.minimum_length < 1:
        parser.error("--minimum-length must be at least 1")

    print("Password Security Auditor")
    print("Your input is hidden and is not stored or transmitted.")

    password = getpass.getpass("Enter a password to audit: ")

    result = evaluate_password(password, args.minimum_length)

    print_report(result)

    if args.csv:
        write_report_csv(result, args.csv)
        print(f"\nPassword-free report saved to: {args.csv}")


if __name__ == "__main__":
    main()
