<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Streamlit-Deployed-red?logo=streamlit&logoColor=white" alt="Streamlit">
  <img src="https://img.shields.io/badge/Google-Gemini%20AI-blue?logo=google&logoColor=white" alt="Gemini">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
</p>

<h1 align="center">ScamShield AI</h1>

<p align="center">
  <strong>AI-powered scam and phishing detection for safer digital communication.</strong><br>
  Analyze suspicious messages, URLs, and screenshots before you click, reply, or pay.
</p>

<p align="center">
  <a href="https://ai-scam-phishing-detector-pk.streamlit.app" target="_blank">
    <img src="https://img.shields.io/badge/Live%20Demo-ONLINE-brightgreen?style=for-the-badge&logo=streamlit&logoColor=white" alt="Live Demo Online">
  </a>
</p>

<p align="center">
  <a href="https://ai-scam-phishing-detector-pk.streamlit.app" target="_blank"><strong>Open Live Demo</strong></a>
  &nbsp;&bull;&nbsp;
  <a href="#how-it-works">How It Works</a>
  &nbsp;&bull;&nbsp;
  <a href="#quick-start">Quick Start</a>
  &nbsp;&bull;&nbsp;
  <a href="#features">Features</a>
</p>

---

## Why ScamShield AI?

Scam and phishing attacks cost individuals and businesses billions every year — and they are getting harder to spot. ScamShield AI combines local rule-based detection with Google's Gemini large language model to give users a second opinion on suspicious content in seconds. Paste a message, drop a screenshot, or submit a link and get back a **risk score, highlighted evidence, and plain-language advice** you can act on.

## Features

| Category | What it does |
|---|---|
| **Explainable AI analysis** | Every verdict comes with highlighted evidence spans, source attribution (AI / Local / URL), and plain-language reasoning — not just a score. |
| **Multi-language support** | Detect scams in **English, Urdu, and Arabic** with localized keyword dictionaries and right-to-left awareness. |
| **URL intelligence** | Typosquatting detection (Levenshtein distance, hyphen-segment aware), homograph attack detection, entropy analysis, URL-shortener flagging, and keyword risk scoring. |
| **Threat intelligence APIs** | Optional Google Safe Browsing and VirusTotal integration for real-time domain reputation checks. |
| **Screenshot OCR** | Extract text from uploaded screenshots via Tesseract OCR, then run the full detection pipeline on the extracted content. |
| **Persistent history** | Analysis results are stored in a local SQLite database with per-entry HTML report export (print-to-PDF ready). |
| **Risk scoring** | 0-100 composite risk score with color-coded verdict: Safe, Suspicious, or Dangerous. |
| **Privacy-first** | API keys stay in `secrets.toml`, user data never leaves the local machine except for the AI analysis call, and a visible security reminder warns against entering real credentials. |

## How It Works

```
User Input (text / URL / screenshot)
        │
        ▼
┌─────────────────────────────────────────┐
│  1. Local Detectors (no AI call needed) │
│     • Urgency / pressure keywords       │
│     • Credential & OTP requests         │
│     • Scam category classifiers         │
│     • URL typosquatting & homograph     │
│     • Suspicious call-to-action phrases │
└─────────────────┬───────────────────────┘
                  │  pre-signals (spans)
                  ▼
┌─────────────────────────────────────────┐
│  2. Gemini AI (structured JSON call)    │
│     • Receives user text + pre-signals  │
│     • Returns risk score, reasoning,    │
│       evidence spans, and advice        │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  3. Unified Rendering                   │
│     • Merge local + AI evidence spans   │
│     • Color-coded source chips          │
│       (🟣 AI  🔵 Local  🟠 URL)          │
│     • Risk score + verdict + advice     │
└─────────────────────────────────────────┘
```

Local detectors run first and feed their findings as **pre-signals** into the Gemini prompt, so the AI can confirm, refine, or add context — producing a more accurate and explainable result than either approach alone.

## Tech Stack

| Layer | Technology |
|---|---|
| **Frontend** | Streamlit |
| **AI Model** | Google Gemini (via `google-genai`) |
| **URL Parsing** | `tldextract`, `idna` |
| **OCR** | Tesseract (`pytesseract` + `Pillow`) |
| **Threat Intel** | Google Safe Browsing API, VirusTotal API |
| **Storage** | SQLite (`sqlite3` stdlib) |
| **Language** | Python 3.10+ |

## Quick Start

### Prerequisites

- Python 3.10 or later
- A [Google Gemini API key](https://aistudio.google.com/apikey) (free tier available)
- *(Optional)* [Tesseract OCR](https://tesseract-ocr.github.io/tessdoc/Installation.html) installed on your system for screenshot analysis

### 1. Clone the repository

```bash
git clone https://github.com/dilawarbhati70-prog/AI-Scam-Detector.git
cd AI-Scam-Detector
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure your API keys

Create `.streamlit/secrets.toml` in the project root:

```toml
GEMINI_API_KEY = "your-gemini-api-key"

# Optional: enable real-time domain reputation
GOOGLE_SAFE_BROWSING_KEY = "your-safe-browsing-key"
VIRUSTOTAL_API_KEY = "your-virustotal-key"
```

### 4. Run the app

```bash
streamlit run app.py
```

The app opens at [http://localhost:8501](http://localhost:8501).

## Project Structure

```
AI-Scam-Detector/
├── app.py                  # Single-file Streamlit application
├── requirements.txt        # Python dependencies
├── .gitignore
├── .streamlit/
│   └── secrets.toml        # API keys (not committed)
└── README.md
```

## Disclaimer

ScamShield AI provides an **AI-assisted assessment** and is not a guaranteed security verdict. Always verify suspicious content through official channels before taking action. Never enter real passwords, OTPs, or banking credentials into any analysis tool.

## Hackathon

This project was built for the **Alibaba Cloud AI Hackathon Pakistan 2026** — demonstrating how generative AI can be applied to cybersecurity and consumer protection at scale.

## License

MIT
