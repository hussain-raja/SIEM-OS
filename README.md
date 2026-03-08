<div align="center">

# 🛡️ SIEM-OS Professional
**The Next-Generation AI-Driven Security Information and Event Management System**

[![FastAPI](https://img.shields.io/badge/Backend-FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/Frontend-React-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://reactjs.org/)
[![Machine Learning](https://img.shields.io/badge/AI-XGBoost%20%26%20Scikit--Learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)](https://xgboost.readthedocs.io/)
[![Database](https://img.shields.io/badge/Database-MongoDB-47A248?style=for-the-badge&logo=mongodb&logoColor=white)](https://www.mongodb.com/)

---

### *Bridging the gap between reactive logging and proactive defense.*
[Overview](#-overview) • [Key Features](#-key-features) • [Architecture](#-architecture)

</div>

## 📖 Overview
**SIEM-OS Professional** is a high-performance, full-stack security platform designed to automate threat detection and response. By combining **Deep Packet Inspection (DPI)** with advanced **Gradient Boosting Algorithms (XGBoost)**, it identifies malicious patterns in real-time and executes active defense measures, such as automated firewall blocking.

---

## ✨ Key Features

#### 🧠 **AI-Powered Detection**
- **Hybrid ML Models:** Utilizes XGBoost, Random Forest, and Isolation Forest for high-precision classification.
- **Traffic Fingerprinting:** Analyzes packet size, flow duration, and request frequency to detect DoS/DDoS and Brute Force attacks.

#### 🛰️ **Intelligent Sensors**
- **DPI Sniffer:** Custom-built Python sniffer using `Scapy` for real-time network layer inspection.
- **Host Monitoring:** Integrated Windows Security Event Log tracking.
- **Honeypot Logic:** Monitors high-risk ports (FTP, SSH, SMB) to trap and log early-stage reconnaissance.

#### 🛡️ **Active Response**
- **Dynamic Firewall Sync:** Automatically pushes malicious IPs detected by AI to the Windows Firewall via `netsh` integration.
- **Instant Alerts:** Real-time push notifications via the `ntfy` protocol.

#### 📊 **Security Operations Center (SOC) Dashboard**
- **Live Visualization:** Real-time threat maps and traffic distribution charts using `Recharts`.
- **Forensic Lab:** Deep-dive into historical logs with advanced filtering and metadata exploration.

🛠️ Tech Stack
- **Frontend:** React.js, Tailwind CSS, Lucide Icons, Recharts.

- **Backend:** FastAPI (Python), Motor (Async MongoDB Atlas), JWT Auth.

- **Machine Learning:** XGBoost, Scikit-Learn, Pandas, NumPy.

- **Network:** Scapy, Win32EvtLog.

---

## 🏗️ Architecture

```mermaid
graph TD
    A[Network Traffic / Win Events] -->|Scapy / Win32API| B(Python Sensor)
    B -->|JSON Over HTTPS| C{FastAPI Backend}
    C -->|Store| D[(MongoDB)]
    C -->|Inference| E[ML Engine: XGBoost/RF/Iso-Forest]
    E -->|Threat Identified| F[Active Defense: Firewall Block]
    C -->|Push Updates| G[React Dashboard]

```


