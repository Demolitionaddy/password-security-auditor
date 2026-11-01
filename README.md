# Password Security Auditor

#### Video Demo: https://youtu.be/a_EqoRfGD0Q

## Description

Password Security Auditor is a command-line Python program that performs a local, educational review of a password. It checks whether the password meets a configurable minimum length, counts the kinds of characters it contains, checks it against a small bundled list of common passwords, estimates theoretical entropy, and provides recommendations. It can optionally export a CSV summary that deliberately excludes the password itself.

The motivation for this project is to explore how Python can be used to build a small defensive security utility. A password can look complicated but still be predictable, and a simple character-count score cannot prove that a password is safe. For that reason, the program presents several separate observations rather than claiming to determine whether a password is impossible to crack. Its output is intended for learning and awareness, not for certifying password security.

## Files

- `project.py` contains the application. `check_length` enforces the selected length policy. `analyze_characters` counts uppercase letters, lowercase letters, digits, symbols, and whitespace. `load_common_passwords` reads the bundled local list, while `check_common_password` compares without case sensitivity. `estimate_entropy` calculates a theoretical estimate using the observed character pool and password length. `evaluate_password` combines the findings into a transparent heuristic assessment. `generate_recommendations` creates suggestions, `write_report_csv` exports a password-free report, and `main` runs the command-line interface.
- `test_project.py` contains pytest tests for the custom functions and important edge cases, including empty input, invalid minimum length, case-insensitive common-password matching, entropy behavior, and ensuring that CSV reports do not contain the password.
- `data/common_passwords.txt` is a small starter list used for local matching. It is not a comprehensive or frequently updated breach corpus.
- `requirements.txt` lists `pytest`, which is needed to run the test suite. The application itself uses Python's standard library.

## How to run

Use Python 3.10 or newer. From the project directory, install the test dependency:

```bash
python3 -m pip install -r requirements.txt
```

Run the tests:

```bash
pytest -v
```

Run the interactive auditor:

```bash
python3 project.py
```

The password is requested through `getpass`, so typed characters are not echoed in the terminal. To change the minimum-length policy:

```bash
python3 project.py --minimum-length 14
```

To export an audit summary:

```bash
python3 project.py --csv reports/audit.csv
```

The CSV contains measurements and recommendations, not the entered password.

## Design decisions and limitations

I used `getpass` instead of a normal `input` prompt to avoid displaying the password while it is typed. The program does not write passwords to files, include them in reports, or transmit them over a network. The CSV export is useful for demonstrating file handling while preserving this privacy rule.

The entropy calculation assumes that each character was selected independently and uniformly from the detected character pool. Real people do not usually choose passwords that way, so the displayed number is a theoretical estimate, not a reliable measure of a human-created password's actual unpredictability. Similarly, the strength label is a simple educational heuristic. The bundled common-password list is intentionally small; a password not found in it is not necessarily uncommon or safe. A real-world tool would need a carefully maintained dataset and more sophisticated, privacy-preserving evaluation.

The project demonstrates functions, dictionaries, sets, file handling, exception handling, command-line arguments, CSV output, and automated testing with pytest. The tests are designed to check both expected behavior and privacy-related requirements.
