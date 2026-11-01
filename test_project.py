
import csv
import pytest

from project import (
    analyze_characters,
    check_common_password,
    check_length,
    estimate_entropy,
    evaluate_password,
    generate_recommendations,
    write_report_csv,
)


def test_check_length():
    assert check_length("short") is False
    assert check_length("twelve_chars") is True
    assert check_length("abc", minimum=3) is True


def test_check_length_rejects_invalid_minimum():
    with pytest.raises(ValueError):
        check_length("anything", minimum=0)


def test_analyze_characters():
    result = analyze_characters("Hello123!")

    assert result["uppercase"] == 1
    assert result["lowercase"] == 4
    assert result["digits"] == 3
    assert result["symbols"] == 1
    assert result["whitespace"] == 0


def test_analyze_empty_password():
    result = analyze_characters("")

    assert result["uppercase"] == 0
    assert result["lowercase"] == 0
    assert result["digits"] == 0
    assert result["symbols"] == 0
    assert result["pool_size"] == 0


def test_common_password_case_insensitive():
    common = {"password123", "qwerty"}

    assert check_common_password("PASSWORD123", common) is True
    assert check_common_password("Qwerty", common) is True
    assert check_common_password("not-in-list", common) is False


def test_entropy_empty_password():
    assert estimate_entropy("") == 0.0


def test_entropy_increases_with_length():
    short = estimate_entropy("abcd")
    longer = estimate_entropy("abcdefgh")

    assert longer > short


def test_common_password_is_very_weak():
    result = evaluate_password("password123")

    assert result["common_password"] is True
    assert result["strength"] == "Very weak"
    assert result["score"] == 0


def test_recommendations_for_empty_password():
    result = generate_recommendations(
        "",
        analyze_characters(""),
        False,
        False,
        12
    )

    assert len(result) > 0


def test_csv_report_does_not_contain_password(tmp_path):
    secret = "NeverWriteThisPassword123!"
    result = evaluate_password(secret)
    output = tmp_path / "audit.csv"

    write_report_csv(result, output)

    contents = output.read_text(encoding="utf-8")

    assert secret not in contents

    with output.open(encoding="utf-8", newline="") as file:
        row = next(csv.DictReader(file))

    assert row["length"] == str(len(secret))
    assert row["strength"] == result["strength"]
