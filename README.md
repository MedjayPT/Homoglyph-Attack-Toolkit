# Homoglyph Attack Toolkit

A simple, local Python web tool designed to generate and detect homoglyph (or IDN Homograph) attacks. This project serves as an educational resource to spread awareness about Unicode-based phishing techniques and is a helpful utility for Capture The Flag (CTF) challenges involving character encoding and domain spoofing.

## ✨ Features

This tool operates as a Flask server, providing two main functionalities via a web interface:

### 🛡️ Detector Mode

Analyzes an input string for non-ASCII characters that closely resemble standard Latin letters.

  * **Character Analysis:** Breaks down the input to show the Unicode Name and Hex Codepoint for every character.
  * **IDN Punycode Detection (New):** Automatically checks strings resembling URLs/Domains for non-ASCII characters and provides the resulting Punycode (e.g., `xn--...`) representation, revealing the true underlying domain name.

### ⚔️ Encoder Mode

Generates multiple malicious spoof variants from a target string (e.g., `apple.com`).

  * **Script-Uniform Spoofs:** Creates variants where multiple characters are replaced exclusively with homoglyphs from a single target Unicode script (Cyrillic, Greek, Armenian, etc.), increasing the spoof's believability.
  * **Single-Character Spoofs:** Creates variants where only one Latin character is swapped for its closest non-Latin homoglyph (the "typo" attack).
  * **Punycode Output:** All generated Unicode spoofs are immediately converted and displayed in their Punycode format, which is the necessary format for launching real-world IDN Homograph attacks.

## 🚀 Getting Started

### Prerequisites

1.  Python 3.x
2.  The Flask web framework and the `idna` library:

<!-- end list -->

```bash
pip install flask idna
```

### Setup and Running

1.  Place the provided data file (`chars.txt`) in the same directory as the Python script.
2.  Run the script:

<!-- end list -->

```bash
python homoglyph_tool.py
```

3.  The server will start on `http://127.0.0.1:8080/` and automatically open the application in your web browser.

## 📚 References

For more detailed information on the threats this tool addresses, refer to the following resources:

  * **Unicode Homoglyph Attack Definition:** [What Is a Homoglyph Attack?](https://inspiroz.com/what-is-a-homoglyph-attack/) (Context for Punycode implementation)
  * **IDN Homograph Attack (Wikipedia):** [IDN homograph attack](https://en.wikipedia.org/wiki/IDN_homograph_attack)
  * **Unicode Consortium's Confusables:** This project is built using data derived from the [Unicode Consortium's Unicode Security Considerations](http://www.unicode.org/reports/tr39/).