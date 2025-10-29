
# 🔍 AI-Assisted Email & Chat Log Forensics

### 👩‍💻 About this Project

While completing a weekly **Digital Forensics Lab** for my cybersecurity course, I realized that simple email-log analysis could evolve into something more powerful.
Instead of limiting the exercise to static datasets, I built an **AI-powered forensic investigation dashboard** that merges **Natural Language Processing (NLP)** with **metadata correlation**.

This Streamlit app simulates how a real-world **Security Operations Center (SOC)** might detect **insider threats** or **phishing attacks** within corporate email and chat communications.
It’s now a full-fledged, interactive **forensic intelligence system** — blending my interests in **AI, Cybersecurity, and Digital Forensics**.

🎯 **[Live Demo → Streamlit Cloud](https://ai-email-chat-forensics-jdamdbcmrmxcwvd3appppjis.streamlit.app/)**

---

## 🧠 Overview

An **AI-driven digital forensics dashboard** that ingests and analyzes **multi-format communication data** — including **CSV, JSON, MBOX, EML, and MSG** files.
The system automatically extracts metadata, applies **NLP-based content analysis**, assigns **threat scores**, and visualizes potential risks across timelines and risk distributions.

---

## ⚙️ Key Features

| Category                            | Description                                                                |
| :---------------------------------- | :------------------------------------------------------------------------- |
| 🧩 **Multi-Format Upload**          | Supports CSV, JSON, MBOX, EML and MSG files for flexible ingestion         |
| 🧠 **AI-Powered Content Analysis**  | Uses TF-IDF and Logistic Regression to classify message risk               |
| 🕵️ **Metadata Correlation Engine** | Flags anomalies in sender domains, timestamps and IP patterns              |
| 📊 **Interactive Visualization**    | Live charts for risk distribution and timeline trends via Plotly           |
| 🧮 **Weighted Threat Scoring**      | Combines NLP probability and metadata weight (α slider adjustable)         |
| 💾 **Exportable Reports**           | Download scored forensic results as CSV for further analysis               |
| 🌗 **Dual-Theme UI**                | Switch instantly between Dark and Light Mode with sparkling blue aesthetic |
| 🧑‍💻 **SOC-Inspired Interface**    | Mimics the workflow of security analysts investigating incidents           |

---

## 🧰 Tech Stack

| Layer                | Tools                                         |
| :------------------- | :-------------------------------------------- |
| **Language**         | Python 3.10+                                  |
| **Libraries**        | Streamlit, Plotly, Scikit-Learn, Pandas, NLTK |
| **Visualization**    | Plotly Express + Custom CSS Themes            |
| **Forensic Parsing** | email.parser, mailbox, WHOIS (optional)       |
| **Deployment**       | Streamlit Cloud / GitHub Actions              |

---

## 🚀 Run Locally

```bash
# Clone the repository
git clone https://github.com/manasweenadgouda22/AI-Email-Chat-Forensics.git
cd AI-Email-Chat-Forensics

# (Optional) create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Launch the dashboard
python -m streamlit run src/dashboard_app.py
```

Then open **[http://localhost:8501](http://localhost:8501)** in your browser.

---

## 🧪 Example Input Formats

### 📧 CSV Example

Create a file named `test_emails.csv` and upload it to the dashboard.

```csv
message,label,sender,timestamp,ip
"Urgent: Please verify your password immediately",1,hr@corp.com,2025-10-24T08:20:00,8.8.8.8
"Meeting rescheduled to 3 PM",0,manager@corp.com,2025-10-24T09:45:00,192.168.1.22
"System maintenance notice",0,it-support@corp.com,2025-10-24T07:00:00,172.16.2.14
"Congratulations! You’ve won a free gift card",1,offers@promo.com,2025-10-24T03:10:00,10.0.0.5
"Reminder: Payroll form submission due today",0,finance@corp.com,2025-10-24T10:05:00,192.168.1.15
"Suspicious login detected on your account",1,security@bankalert.com,2025-10-24T02:15:00,23.55.44.11
```

### 📬 Email Formats

You can also upload `.eml`, `.msg`, or `.mbox` files directly.
The parser automatically extracts sender, receiver, subject, timestamp, and message body for analysis.

---

## 🧩 What I Learned

Building this project taught me how to:

* Integrate **digital forensics principles** with **machine learning models**.
* Design a **multi-source parsing pipeline** for emails and chat logs.
* Apply TF-IDF and Logistic Regression for **threat classification**.
* Create a responsive **Streamlit UI** with dual-theme support and animated elements.
* Combine **metadata heuristics** and AI probabilities for risk scoring.
* Think like a SOC analyst evaluating anomalous communication patterns.

---

## 🚧 Future Enhancements

* 🧠 Integrate **BERT/DistilBERT** for deep semantic analysis.
* 💬 Extend support to chat platforms (Slack, Teams, Discord).
* 🌍 Add **GeoIP mapping** and sender location visualization.
* ⚙️ Enable real-time alerting with email/SIEM integration.
* ☁️ Support cloud log ingestion via AWS S3 or Elasticsearch.

---

## 🙏 Acknowledgements

This project was inspired by my **Digital Forensics and Investigation Lab** coursework.
Thanks to my professor and peers for their feedback, which helped transform a weekly lab into a production-grade forensic dashboard.

---

⭐ If you found this project useful, please **star the repo** and connect with me on [LinkedIn](https://www.linkedin.com/in/mnadgoud22/)!
I’m always open to collaboration and cybersecurity discussions 🚀


