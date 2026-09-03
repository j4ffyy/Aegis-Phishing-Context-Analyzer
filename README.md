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

## How to Run Locally

1. Open `Aegis_Prototype/index.html` in your browser
2. Click any email in the left pane to view its content
3. Use the analyzer overlay features to see the phishing risk score and insights

## Development Notes

- This is a static prototype intended for demonstration only
- No backend or server-side logic is required
- The analyzer is simulated with hardcoded sample data

## Repository Contents

- `Aegis_Prototype/`
  - `index.html`
  - `styles.css`
  - `app.js`
- `.gitignore`
- `README.md`

## License

This repository is currently a self-contained prototype. Feel free to adapt it for your capstone demo or research showcase.
