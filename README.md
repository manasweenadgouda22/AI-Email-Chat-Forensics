# 🔍 AI-Assisted Email & Chat Log Forensics  

### 👩‍💻 About this Project
While working on my weekly **Digital Forensics Lab** assignment for my cybersecurity course, I realized the exercises on analyzing email and chat logs could evolve into something bigger.  
Instead of just following the lab steps, I decided to build an **AI-powered forensic investigation dashboard** that combines Natural Language Processing (NLP) and metadata correlation.  
This project started as a class experiment — but quickly turned into a full-fledged **Streamlit app** that simulates how a real **Security Operations Center (SOC)** might detect insider threats and phishing attacks in corporate communications.  
It became one of my most rewarding learning experiences, blending my interests in **AI, cybersecurity, and digital forensics**.

🎯 **[Live Demo → Open on Streamlit Cloud](https://ai-email-chat-forensics-jdamdbcmrmxcwvd3appppjis.streamlit.app/)**  

---

## 🧠 Overview  
An **AI-driven digital forensics dashboard** that analyzes corporate email and chat logs to identify insider threats and phishing attempts.  
The system applies **Natural Language Processing (NLP)** and **metadata correlation** to classify messages, compute threat scores, and visualize high-risk communications — all through an interactive Streamlit interface.

---

## ⚙️ Features  
- 🧩 **NLP-based content analysis** (TF-IDF + Logistic Regression)  
- 🕵️ **Metadata correlation** — sender domain, timestamp anomalies, IP pattern scoring  
- 📊 **Interactive Streamlit dashboard** with dynamic charts & timelines  
- 🧮 **Threat scoring engine** combining AI probability + metadata weight  
- 📑 **Downloadable forensic report (CSV)** for investigation documentation  
- ⚖️ Designed to align with **Daubert-standard admissibility** principles  

---

## 🧰 Tech Stack  
| Layer | Tools |
|:------|:------|
| **Language** | Python 3.10+ |
| **Libraries** | Streamlit, Plotly, Scikit-Learn, Pandas, NLTK, Transformers |
| **Visualization** | Plotly Express, Streamlit |
| **Forensics** | WHOIS, Metadata parsing |
| **Deployment** | Streamlit Cloud + GitHub Actions (optional) |

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

# Launch the app
python -m streamlit run src/dashboard_app.py
````

Open **[http://localhost:8501](http://localhost:8501)** in your browser.

---

## 🧪 Example CSV Format

To test the app, copy the text below into a file named **`test_emails.csv`**, then upload it in the dashboard.

```csv
message,label,sender,timestamp,ip
"Urgent: Please verify your password immediately",1,hr@corp.com,2025-10-24T08:20:00,8.8.8.8
"Meeting rescheduled to 3 PM",0,manager@corp.com,2025-10-24T09:45:00,192.168.1.22
"System maintenance notice",0,it-support@corp.com,2025-10-24T07:00:00,172.16.2.14
"Congratulations! You’ve won a free gift card",1,offers@promo.com,2025-10-24T03:10:00,10.0.0.5
"Reminder: Payroll form submission due today",0,finance@corp.com,2025-10-24T10:05:00,192.168.1.15
"Suspicious login detected on your account",1,security@bankalert.com,2025-10-24T02:15:00,23.55.44.11
```

---

## 🧩 What I Learned

Building this project helped me:

* Combine **digital forensics concepts** with **machine learning workflows**.
* Implement **NLP models** (TF-IDF and Logistic Regression) for cybersecurity use cases.
* Practice **data cleaning, feature extraction**, and **metadata scoring**.
* Deploy a **Streamlit web app** and manage environment dependencies using Git and virtual environments.
* Think like a **SOC analyst**, analyzing communication data for threat patterns.

---

## 🚧 Future Enhancements

* Integrate **BERT or DistilBERT models** for deeper semantic threat detection.
* Extend functionality to **chat platforms** like Slack or Microsoft Teams.
* Add **real-time alerting** and visualization dashboards.
* Build a **GeoIP-based map view** for sender locations.
* Incorporate **log ingestion pipelines** using AWS or Elasticsearch for enterprise-scale use.

---

## 🙏 Acknowledgements

This project was inspired by my **Digital Forensics and Investigation Lab** coursework.
Special thanks to my professor and classmates for their feedback, which encouraged me to expand the weekly lab into a full-fledged AI-based forensic system.

---

⭐ If you found this project interesting, feel free to **star the repo** and connect with me on [LinkedIn](https://www.linkedin.com/in/mnadgoud22/)!
I’m always open to feedback, collaborations, or cybersecurity discussions. 😊

```

