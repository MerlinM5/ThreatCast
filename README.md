# ThreatCast: AI-Based Network Attack Forecasting

## Overview
ThreatCast is a unified, next-generation network traffic analysis and simulated threat detection platform, designed for speed and clarity in forensic investigation and real-time monitoring. Developed by Team **ZeroTrace** for Smart India Hackathon 2026.

## 🔗 Live Prototype Demo
> **[Click here to view the Live ThreatCast Prototype](YOUR_DEPLOYMENT_LINK_HERE)** 

## 📸 Prototype Preview
*(Replace the image below with a real screenshot of your dashboard running)*
![ThreatCast Dashboard Placeholder](https://via.placeholder.com/800x400.png?text=ThreatCast+Dashboard+-+Upload+Screenshot+Here)

## Features
- **AI-Based Forecasting:** Predicts the likelihood of an attack in the upcoming time window using multi-feature behavioral profiling.
- **Hybrid Detection:** Combines supervised machine learning and anomaly detection.
- **Live Threat Analysis:** Provides dynamic, real-time visualization of threats segmented by severity (Critical, High, Medium).
- **Explainable AI:** Generates early warnings highlighting the precise traffic patterns responsible for the forecast.
- **Automated Response:** Simulates WAF integration and SOAR forensics for proactive defense.

## Technologies Used
- **Backend:** Python, Flask, Custom TrafficEngine
- **Frontend:** HTML5, CSS3, JavaScript, Chart.js
- **Machine Learning / AI:** XGBoost, Isolation Forest, PyTorch (simulated via Hybrid Detection system)
- **Telemetry Processing:** eBPF, Zeek, NetFlow (simulated packet processing)

## Getting Started

### Prerequisites
- Python 3.8+
- Requirements listed in `requirements.txt`

### Installation
1. Clone the repository.
2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Application
To start the application, run:
```bash
python app.py
```
Navigate to `http://localhost:5000` in your web browser to access the ThreatCast dashboard.

