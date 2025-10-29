import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Internal modules
from src.universal_parser import parse_file
from data_cleaner import load_and_clean
from feature_engineer import extract_metadata_features
from threat_scoring import compute_metadata_score, compute_threat_score, label_risk


# ----------------------------------------------------
# Page Setup
# ----------------------------------------------------
st.set_page_config(page_title="AI Email & Chat Forensics", layout="wide")

# Sidebar Theme Toggle
st.sidebar.title("⚙️ Settings")
theme = st.sidebar.radio("Select Theme", ["Dark Mode", "Light Mode"], index=0)


# ----------------------------------------------------
# Dynamic Styling
# ----------------------------------------------------
if theme == "Dark Mode":
    background_css = """
    background: radial-gradient(circle at top left, #071E3D 0%, #0B2A59 60%, #081229 100%);
    color: #e2e8f0;
    """
    accent_color = "#00b4d8"
    secondary_color = "#0077b6"
    sidebar_bg = "#0c2340"
    text_color = "#e2e8f0"
    button_text_color = "white"
else:
    background_css = """
    background: linear-gradient(180deg, #ffffff 0%, #f8f9fb 100%);
    color: #1a1a1a;
    """
    accent_color = "#0077b6"
    secondary_color = "#00b4d8"
    sidebar_bg = "#edf6f9"
    text_color = "#1a1a1a"
    button_text_color = "white"

# Apply CSS
st.markdown(f"""
<style>
[data-testid="stAppViewContainer"] {{
    {background_css}
    font-family: 'Inter', sans-serif;
}}
[data-testid="stHeader"] {{
    background: transparent;
    height: 0rem;
}}
[data-testid="stSidebar"] {{
    background: {sidebar_bg};
    color: {text_color};
}}
h1, h2, h3 {{
    color: {accent_color if theme=="Light Mode" else "#A7C7E7"};
    font-weight: 700;
}}
h2::after, h3::after {{
    content: "";
    display: block;
    height: 2px;
    width: 60px;
    margin-top: 6px;
    background: linear-gradient(90deg, {accent_color}, {secondary_color});
}}
/* Buttons */
button[kind="primary"], .stButton>button {{
    background: linear-gradient(90deg, {secondary_color}, {accent_color});
    color: {button_text_color} !important;
    border-radius: 8px;
    font-weight: 600;
    border: none;
}}
button:hover {{
    background: linear-gradient(90deg, {accent_color}, {secondary_color});
}}
/* File uploader + Browse button fix */
[data-testid="stFileUploader"] {{
    background: rgba(255, 255, 255, 0.08);
    border-radius: 12px;
    padding: 1rem;
    border: 1px solid rgba(255, 255, 255, 0.2);
    color: {text_color};
}}
[data-testid="stFileUploader"] label div[role='button'] {{
    background: {secondary_color};
    color: white !important;
    border-radius: 8px;
    padding: 0.4rem 0.8rem;
    font-weight: 600;
}}
[data-testid="stFileUploader"] p {{
    color: {text_color} !important;
}}
/* File name text color fix */
[data-testid="stFileUploaderFileName"] {{
    color: {text_color} !important;
    font-weight: 600;
}}
/* DataFrame */
.stDataFrame {{
    background: rgba(255, 255, 255, 0.05);
    border-radius: 12px;
    padding: 1rem;
}}
.stDataFrame table {{
    color: inherit !important;
}}
/* Alerts */
.stAlert {{
    background-color: rgba(0, 119, 182, 0.15);
    border: 1px solid {accent_color};
    border-radius: 10px;
    color: {text_color};
}}
/* Download button */
.stDownloadButton>button {{
    background: linear-gradient(90deg, {accent_color}, {secondary_color});
    color: white !important;
    border-radius: 8px;
    font-weight: 600;
}}
.stDownloadButton>button:hover {{
    background: linear-gradient(90deg, {secondary_color}, {accent_color});
}}
/* Plot background */
.plotly {{
    background: rgba(255, 255, 255, 0.08) !important;
    border-radius: 12px;
    padding: 1rem;
}}
/* Slider fix */
.stSlider label {{
    color: {accent_color if theme=="Light Mode" else "#A7C7E7"} !important;
    font-weight: 600;
}}
.stSlider div[role='slider'] {{
    background: {accent_color} !important;
}}
hr {{
    border: none;
    height: 1px;
    background: linear-gradient(90deg, {secondary_color}, {accent_color}, transparent);
    margin: 20px 0;
}}
/* Sidebar radio buttons fix */
section[data-testid="stSidebar"] label {{
    color: {text_color} !important;
    font-weight: 600;
}}
</style>
""", unsafe_allow_html=True)


# ----------------------------------------------------
# Header
# ----------------------------------------------------
st.title("🔍 AI-Assisted Email & Chat Log Forensics")
st.markdown("Analyze digital communications using NLP & metadata correlation to flag potentially risky or malicious behavior.")

# Status line
st.markdown(f"<div style='color:{accent_color};font-size:16px;font-weight:600;'>🟢 System ready — multi-format ingest active (CSV • JSON • MBOX • EML • MSG)</div>", unsafe_allow_html=True)

# ----------------------------------------------------
# File Upload Section
# ----------------------------------------------------
st.markdown(f"<h3 style='font-weight:700; margin-top:10px; color:{accent_color if theme=='Light Mode' else '#A7C7E7'};'>📂 Upload your email or chat data</h3>", unsafe_allow_html=True)

uploaded = st.file_uploader("", type=["csv", "mbox", "eml", "msg", "json"])

if uploaded is not None:
    file_ext = os.path.splitext(uploaded.name)[1].lower()

    try:
        with st.spinner(f"Parsing {file_ext.upper()} file..."):
            df = parse_file(uploaded, file_ext)
        st.success(f"✅ Loaded {len(df)} messages successfully!")
        st.subheader("Data Preview")
        st.dataframe(df.head(20))
    except Exception as e:
        st.error(f"❌ Could not parse file: {e}")
        st.stop()

    df = load_and_clean(df, text_col="message")

    if "label" in df.columns:
        st.subheader("Model Training & Threat Scoring")

        tfidf = TfidfVectorizer(stop_words="english", max_features=5000)
        X = tfidf.fit_transform(df["message"].astype(str))
        y = df["label"]
        model = LogisticRegression(max_iter=1000)
        model.fit(X, y)

        if len(set(y)) == 2:
            nlp_prob = model.predict_proba(X)[:, 1]
        else:
            nlp_prob = model.predict_proba(X).max(axis=1)

        df_feat = extract_metadata_features(df, sender_col="sender",
                                            ts_col="timestamp", ip_col="ip",
                                            msg_col="message")
        meta_score = compute_metadata_score(df_feat)

        st.markdown("#### Weight Adjustment")
        alpha = st.slider("Weight for NLP Probability (α)", 0.0, 1.0, 0.7, 0.05)
        threat = compute_threat_score(pd.Series(nlp_prob), meta_score, alpha=alpha)
        risk = label_risk(threat)

        out = df_feat.copy()
        out["nlp_prob"] = nlp_prob
        out["metadata_score"] = meta_score
        out["threat_score"] = threat
        out["risk"] = risk

        st.subheader("📊 Threat Overview")
        fig = px.histogram(out, x="risk", title="Risk Distribution",
                           color="risk", color_discrete_sequence=px.colors.qualitative.Safe)
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("📈 Timeline View")
        if "timestamp" in out.columns:
            try:
                out_sorted = out.copy()
                out_sorted["timestamp"] = pd.to_datetime(out_sorted["timestamp"], errors="coerce")
                fig2 = px.scatter(out_sorted.sort_values("timestamp"),
                                  x="timestamp", y="threat_score",
                                  color="risk",
                                  hover_data=["sender", "nlp_prob", "metadata_score"])
                fig2.update_traces(mode="lines+markers")
                st.plotly_chart(fig2, use_container_width=True)
            except Exception as e:
                st.warning(f"⚠️ Could not render timeline: {e}")

        st.subheader("🚨 Flagged Messages (High Risk)")
        st.dataframe(out[out["risk"] == "High"].head(50))

        st.download_button(
            "💾 Download Scored CSV",
            data=out.to_csv(index=False).encode("utf-8"),
            file_name="forensic_scored_results.csv",
            mime="text/csv"
        )
    else:
        st.warning("⚠️ No 'label' column found. Please provide labeled data for demo training.")
else:
    st.info("Upload your email or chat log (CSV, MBOX, EML, MSG, JSON) to begin.")
