# 🛡️ Real-Time UDP-Based DDoS Detection Using Machine Learning

A lightweight, real-time detection system designed to identify **UDP-based DDoS attacks** using a trained **XGBoost model** and an interactive **Streamlit** interface. The system supports both offline file analysis and live traffic monitoring via **TShark** and **CICFlowMeter**.

---

## 📌 Project Description

This project focuses on detecting Distributed Denial-of-Service (DDoS) attacks, particularly those using the User Datagram Protocol (UDP). By leveraging machine learning, the system can:

- Monitor live traffic or analyze offline datasets.
- Detect anomalies in network flow patterns.
- Assist network analysts by reducing manual inspection.

The goal is to provide a simple yet powerful tool for security enthusiasts, researchers, and students.

---

## 🗂️ Datasets Used

The XGBoost model was trained using publicly available datasets containing labeled network traffic:

- **CICDDoS2019**  
  Source: Canadian Institute for Cybersecurity  
  Features extracted using **CICFlowMeter**  
  Includes multiple types of DDoS attacks (UDP, SYN, TCP, etc.)

- **CICIDS2017 (Selected UDP Attack Flows)**  
  Source: Canadian Institute for Cybersecurity  
  Used to supplement benign traffic and UDP attack flows  
  Extracted features standardized to match the CICDDoS2019 format

These datasets provided labeled network flows categorized as **BENIGN** or **DDoS**, with a focus on **UDP-based traffic** for binary classification.

> ⚠️ **Note**: Accuracy may still be shaky due to dataset limitations, such as lack of modern attack variations and insufficient real-world diversity.

---

## 🛠️ Tools & Frameworks Used

- **Python 3.10**
- [XGBoost](https://xgboost.readthedocs.io/) – Machine learning model
- [Streamlit](https://streamlit.io/) – Web-based UI
- [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) – Command-line packet capture
- [CICFlowMeter](https://www.unb.ca/cic/research/applications.html) – Network flow feature extractor
- **pandas, numpy** – Data handling
- **matplotlib** – Visualization
- **scikit-learn** – Label encoding and preprocessing
- **subprocess, tempfile, os** – System operations

---

## 📊 Model Performance Notes

While the model performs well under testing and controlled simulations, please note:

> **⚠️ Accuracy may still be shaky due to dataset limitations.**

- The dataset lacks diversity and scale to fully represent real-world UDP traffic.
- Many benign flows and newer DDoS variants are not present in the training data.
- Currently focuses only on Layer 3 and Layer 4 features (IP, port, protocol, flow stats).

Improvements in data collection and model tuning are planned to address these limitations.

---

## 🚀 Future Enhancements

- 🧠 Add Layer 7 (Application Layer) inspection capability.
- 📦 Support for more comprehensive, real-world DDoS datasets.
- 📈 Improve classification metrics through enhanced feature engineering.
- 🔔 Integrate alerting system (Telegram/email).
- 🌐 Option to deploy as a lightweight SIEM for broader monitoring.

---
