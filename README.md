# REGRESSIONARY
> **STATUS: SYSTEM ONLINE**
> 
> A high-performance, browser-based statistical engine built for econometric regressions, OLS matrices, and time series forecasting.

![Regressionary Terminal](https://img.shields.io/badge/UI-Brutalist_Terminal-black?style=flat-square)
![Build](https://img.shields.io/badge/Build-Stateless-success?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.x-blue?style=flat-square)

Regressionary is a lightweight, pure-math diagnostic tool designed for economics students, researchers, and data analysts. It bypasses the need for heavy desktop software by performing complex statistical modeling directly in the browser. 

---

## 01. CORE MODULES
* **The Math Engine:** Powered by `statsmodels` and `SciPy`, executing precise Ordinary Least Squares (OLS) regressions.
* **The Data Vault:** A built-in repository of econometric datasets ready for instant loading without uploading local files.
* **Diagnostic Reporting:** Generates formal academic output tables featuring Coefficients, Standard Errors, R-Squared, Adjusted R-Squared, F-Statistic probabilities, and standard significance stars (`***`).
* **Progressive Web App (PWA):** Fully installable on mobile devices with a native app-like experience.

---

## 02. ARCHITECTURE & "GHOST PROTOCOL"
To maintain high performance and deploy successfully on strict 512MB RAM cloud environments (like Render's free tier), this app utilizes a custom **Stateless Architecture**.

* **Zero Database:** Heavy SQL databases (`SQLAlchemy`) and user-auth packages (`Flask-Login`) were entirely stripped out. 
* **Ghost Protocol:** User sessions are managed statelessly using cryptographically secure UUIDs. This ties a user's device to their uploaded data without requiring an account, login, or database row.
* **Ephemeral Memory:** Uploaded `.csv` and `.xlsx` datasets exist only in active memory (RAM) and are automatically wiped by the server on sleep cycles, preventing storage bloat and memory leaks.
* **RAM Optimization:** The environment is strictly curated. Heavy visual export libraries (like `kaleido`) were removed to prevent Out-Of-Memory (OOM) crashes, keeping the app footprint safely under 100MB during idle.

---

## 03. THE TECH STACK
* **Backend:** Python, Flask, Gunicorn
* **Math & Data:** Pandas, NumPy, SciPy, Statsmodels
* **Frontend:** HTML5, TailwindCSS, Jinja2
* **Deployment:** Render 

---

## 04. LOCAL DEPLOYMENT PROTOCOL
To spin up the Regressionary terminal on your local machine:

**1. Clone the repository:**
```bash
git clone [https://github.com/yourusername/regressionary.git](https://github.com/yourusername/regressionary.git)
cd regressionary

