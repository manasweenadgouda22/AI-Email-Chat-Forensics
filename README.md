# AI-Assisted Email and Chat Log Forensics

A master's-level cybersecurity project integrating NLP and digital forensics to detect insider threats, phishing attempts, and social engineering within enterprise communication datasets.

## Overview
This project automates the detection of suspicious or malicious messages from email and chat logs using Natural Language Processing (NLP) and metadata correlation. It’s designed for DFIR and SOC teams to accelerate investigations and provide Daubert-standard forensic reporting.

## Features
- NLP-based content classification (TF-IDF + BERT)
- Metadata correlation (sender domains, timestamps, IPs)
- Threat likelihood scoring engine
- Interactive Streamlit dashboard
- Automated forensic PDF report generator
- Chain-of-custody logging with SHA-256 hashing

## Tech Stack
**Language:** Python 3.10+  
**Libraries:** Scikit-Learn, HuggingFace Transformers, NLTK, Pandas, Plotly, Streamlit  
**Deployment:** Docker, GitHub Actions

## Quick Start
```bash
git clone https://github.com/<your-username>/AI-Email-Chat-Forensics.git
cd AI-Email-Chat-Forensics
pip install -r requirements.txt
streamlit run src/dashboard_app.py
```

## Example Workflow
1. Upload email or chat logs (CSV, JSON, or MBOX).
2. The system extracts features (content + metadata).
3. Model classifies messages as benign, phishing, or insider threat.
4. Dashboard visualizes patterns & generates PDF forensic report.

## Dataset References
- Enron Email Dataset: https://www.cs.cmu.edu/~enron/
- SMS Spam Collection Dataset: https://archive.ics.uci.edu/ml/datasets/sms+spam+collection
- Custom synthetic chat dataset (you can place samples in `data/samples/`).

## Repository Structure
```
AI-Email-Chat-Forensics/
├── data/
│   ├── raw/
│   ├── processed/
│   └── samples/
├── notebooks/
│   ├── 01_preprocessing.ipynb
│   ├── 02_feature_extraction.ipynb
│   ├── 03_model_training.ipynb
│   ├── 04_threat_scoring.ipynb
│   └── 05_visualization.ipynb
├── src/
│   ├── data_cleaner.py
│   ├── feature_engineer.py
│   ├── model_trainer.py
│   ├── threat_scoring.py
│   ├── dashboard_app.py
│   └── report_generator.py
├── reports/
│   └── sample_forensic_report.pdf
├── Dockerfile
├── requirements.txt
├── README.md
└── LICENSE
```

## License
MIT License © 2025 Manaswee Balvant Nadgouda
