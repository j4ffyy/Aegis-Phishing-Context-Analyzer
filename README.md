# Aegis Phishing Context Analyzer

Aegis is a browser-based phishing analysis prototype built as a mock email client interface. It simulates advanced phishing detection with multi-layered checks, explainable AI insights, and realistic email scenarios.

## Prototype Overview

This project is a static web prototype located in the `Aegis_Prototype/` folder. It includes:

- `index.html` - the main interface for the mock email client and Aegis analyzer overlay
- `styles.css` - visual styling for the simulated Gmail-like interface
- `app.js` - sample email data, attack detection flow, analysis badge display, and UI behavior

## Key Features

- Mock webmail inbox with clickable email items
- Simulated phishing analysis overlay for selected emails
- Risk scoring and layered threat detection details
- Explainable AI feedback for each example email
- Basic interaction flows for analyzing and reviewing content

## Sample Email Scenarios

The prototype includes four example emails demonstrating:

1. A safe internal HR email
2. A critical phishing email with malicious attachment
3. A warning-level BEC-style request from a suspicious sender
4. A malicious security certificate scam with embedded link

## Getting Started & Chrome Extension Setup

> 🚀 **Fresh Clone? Read the Complete Step-by-Step Setup Guide:**
> 👉 **[SETUP_GUIDE.md](SETUP_GUIDE.md)** 👈
>
> The guide covers backend virtual environment setup, downloading the ONNX DistilBERT model, running the FastAPI server, loading the unpacked extension in Google Chrome (`chrome://extensions`), and testing live on Gmail.

---

## Repository Structure

- **[`aegis-extension/`](aegis-extension/)** — Chrome Extension (Manifest V3) for Gmail with client-side PII scrubbing, local heuristics, and in-Gmail overlay UI.
- **[`aegis-backend/`](aegis-backend/)** — Lightweight FastAPI backend hosting the DistilBERT ONNX classification model, VirusTotal URL scanner, and XAI generator.
- **[`Aegis_Prototype/`](Aegis_Prototype/)** — Standalone mock webmail client demonstrating 4 simulated phishing scenarios without needing a live Gmail account.
- **[`docs/`](docs/)** — Capstone development plans, presentation defense guides, and technical specifications.
- **[`SETUP_GUIDE.md`](SETUP_GUIDE.md)** — Step-by-step setup instructions for running the extension and backend on Google Chrome.

## License

This repository is developed for MMDC Capstone 1 research.

