# OWASP Top 10 2025 Interactive Lab

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-Active-success.svg)
![React](https://img.shields.io/badge/react-18.2-61dafb.svg)
![Tailwind](https://img.shields.io/badge/tailwindcss-3.0-38bdf8.svg)

## 🛡️ Overview

The **OWASP Top 10 2025 Interactive Lab** is a cutting-edge educational platform designed to simulate, explain, and remediate the most critical security risks facing modern web applications. 

Unlike static documentation, this lab offers **hands-on simulations**, **gamified audits**, and **DevOps pipeline integration** visualizations to bridge the gap between theoretical knowledge and practical application security.

## 🚀 Key Features

*   **Interactive Attack Simulations**: Real-time mock terminals allowing users to execute SQL Injection, IDOR, and Crypto attacks safely in a sandbox.
*   **Secure Code Patcher**: Compare "Vulnerable" vs. "Secure" code snippets with syntax highlighting and diff views.
*   **CI/CD Pipeline Visualizer**: Watch how automated tools (SAST, DAST, SCA) detect specific vulnerabilities in a simulated DevOps workflow.
*   **Gamified Scoring**: Track your rank from "Script Kiddie" to "CISO" as you solve audits and fix vulnerabilities.
*   **AI-Powered Remediation**: Integrated with **Google Gemini** to generate context-aware code fixes and remediation advice on demand.
*   **Cyberpunk UI**: Immersive "Hacker" aesthetic with CRT scanlines, glitches, and terminal effects.

## 📋 The OWASP Top 10 (2025)

This lab covers the anticipated 2025 standard (building on 2021 trends):

1.  **A01: Broken Access Control**
2.  **A02: Cryptographic Failures**
3.  **A03: Injection**
4.  **A04: Insecure Design**
5.  **A05: Security Misconfiguration**
6.  **A06: Vulnerable and Outdated Components**
7.  **A07: Identification and Authentication Failures**
8.  **A08: Software and Data Integrity Failures**
9.  **A09: Security Logging and Monitoring Failures**
10. **A10: Server-Side Request Forgery (SSRF)**

*Bonus Modules included: CSRF & Clickjacking*

## 🛠️ Installation & Setup

1.  **Clone the repository**
    ```bash
    git clone https://github.com/yourusername/owasp-2025-lab.git
    cd owasp-2025-lab
    ```

2.  **Install Dependencies**
    ```bash
    npm install
    ```

3.  **Configure API Key (Optional)**
    To enable the AI Remediation Assistant, create a `.env` file and add your Google Gemini API key:
    ```env
    REACT_APP_GEMINI_API_KEY=your_api_key_here
    ```
    *Note: The lab functions fully without the API key, except for the "Ask AI" feature.*

4.  **Start the Development Server**
    ```bash
    npm start
    ```

## ⚠️ Disclaimer

This application contains simulated security vulnerabilities and attack scenarios. It is intended for **EDUCATIONAL PURPOSES ONLY**. 

*   Do not use the techniques demonstrated here on systems you do not own or have explicit permission to test.
*   The code snippets labeled "Vulnerable" are intentionally insecure; do not use them in production.

## 🤝 Contributing

Contributions are welcome! Please submit a Pull Request or open an Issue to suggest new simulations or features.

## 📄 License

This project is open source and available under the [MIT License](LICENSE).