import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.io as pio
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import os, sys

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
    pio.templates.default = "plotly_dark"
    chart_paper = "rgba(0,0,0,0)"
    chart_plot = "rgba(0,0,0,0)"
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
    pio.templates.default = "plotly_white"
    chart_paper = "rgba(255,255,255,0)"
    chart_plot = "rgba(255,255,255,0)"

# ----------------------------------------------------
# CSS Styling
# ----------------------------------------------------
st.markdown(f"""
<style>
[data-testid="stAppViewContainer"] {{
    {background_css}
    font-family: 'Inter', sans-serif;
}}
[data-testid="stHeader"] {{ background: transparent; height: 0rem; }}
[data-testid="stSidebar"] {{ background: {sidebar_bg}; color: {text_color}; }}
section[data-testid="stSidebar"] * {{ color: {text_color} !important; }}

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

/* ---- File uploader text fix ---- */
[data-testid="stFileUploader"] {{
    background: {('rgba(255,255,255,0.08)' if theme=='Dark Mode' else 'rgba(0,0,0,0.04)')};
    border-radius: 12px;
    padding: 1rem;
    border: 1px solid {('rgba(255,255,255,0.2)' if theme=='Dark Mode' else 'rgba(0,0,0,0.12)')};
}}

[data-testid="stFileUploader"] * {{
    color: {text_color} !important;
}}

[data-testid="stFileUploader"] div[role='button'],
[data-testid="stFileUploader"] span,
[data-testid="stFileUploader"] p,
[data-testid="stFileUploader"] small {{
    color: {('white' if theme=='Light Mode' else text_color)} !important;
}}

/* Sparkling blue theme for the Browse Files button */
[data-testid="stFileUploader"] label div[role='button'] {
    background: linear-gradient(90deg, #00b4d8, #0077b6, #90e0ef);
    color: white !important;
    border-radius: 10px;
    padding: 0.5rem 1.1rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    box-shadow: 0 0 12px rgba(0, 180, 216, 0.6), 0 0 24px rgba(0, 119, 182, 0.3);
    transition: all 0.3s ease-in-out;
    animation: shimmer 3s infinite linear;
    background-size: 200% 100%;
}

[data-testid="stFileUploader"] label div[role='button']:hover {
    background-position: right center;
    box-shadow: 0 0 18px rgba(0, 180, 216, 0.9), 0 0 32px rgba(0, 119, 182, 0.6);
    transform: scale(1.03);
}

/* Shimmer animation */
@keyframes shimmer {
    0% { background-position: 0% 50%; }
    50% { background-position: 100% 50%; }
    100% { background-position: 0% 50%; }
}



/* ---- Buttons ---- */
.stDownloadButton>button, .stButton>button {{
    background: linear-gradient(90deg, {accent_color}, {secondary_color});
    color: white !important;
    border-radius: 8px;
    font-weight: 700;
    border: none;
}}
.stDownloadButton>button:hover, .stButton>button:hover {{
    background: linear-gradient(90deg, {secondary_color}, {accent_color});
}}

/* ---- DataFrame styling ---- */
.stDataFrame {{
    background: {('rgba(255,255,255,0.05)' if theme=='Dark Mode' else 'rgba(0,0,0,0.03)')};
    border-radius: 12px;
    padding: 1rem;
}}
.stAlert {{
    background-color: {('rgba(0, 119, 182, 0.15)' if theme=='Light Mode' else 'rgba(0, 119, 182, 0.2)')};
    border: 1px solid {accent_color};
    border-radius: 10px;
    color: {text_color};
}}
hr {{
    border: none;
    height: 1px;
    background: linear-gradient(90deg, {secondary_color}, {accent_color}, transparent);
    margin: 20px 0;
}}
</style>
""", unsafe_allow_html=True)


# ----------------------------------------------------
# Header
# ----------------------------------------------------
st.title("🔍 AI-Assisted Email & Chat Log Forensics")
st.markdown("Analyze digital communications using NLP & metadata correlation to flag potentially risky or malicious behavior.")
st.markdown(
    f"<div style='color:{accent_color};font-size:16px;font-weight:600;'>🟢 System ready — multi-format ingest active (CSV • JSON • MBOX • EML • MSG)</div>",
    unsafe_allow_html=True
)

# ----------------------------------------------------
# File Upload
# ----------------------------------------------------
st.markdown(
    f"<h3 style='font-weight:700;margin-top:10px;color:{accent_color if theme=='Light Mode' else '#A7C7E7'};'>📂 Upload your email or chat data</h3>",
    unsafe_allow_html=True
)

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

    # ------------------------------------------------
    # NLP + Threat Scoring
    # ------------------------------------------------
    if "label" in df.columns:
        st.subheader("Model Training & Threat Scoring")

        tfidf = TfidfVectorizer(stop_words="english", max_features=5000)
        X = tfidf.fit_transform(df["message"].astype(str))
        y = df["label"]

        model = LogisticRegression(max_iter=1000)

        if len(set(y)) >= 2:
            model.fit(X, y)
            nlp_prob = model.predict_proba(X)[:, 1]
        else:
            st.warning("⚠️ Only one label class found — skipping model training. Using metadata-based scoring only.")
            nlp_prob = [0.5] * len(y)

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

        # Charts
        st.subheader("📊 Threat Overview")
        fig = px.histogram(out, x="risk", title="Risk Distribution",
                           color="risk", color_discrete_sequence=px.colors.qualitative.Safe,
                           template=pio.templates.default)
        fig.update_layout(paper_bgcolor=chart_paper, plot_bgcolor=chart_plot)
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("📈 Timeline View")
        if "timestamp" in out.columns:
            try:
                out["timestamp"] = pd.to_datetime(out["timestamp"], errors="coerce")
                fig2 = px.scatter(out.sort_values("timestamp"),
                                  x="timestamp", y="threat_score",
                                  color="risk",
                                  hover_data=["sender", "nlp_prob", "metadata_score"],
                                  template=pio.templates.default)
                fig2.update_traces(mode="lines+markers")
                fig2.update_layout(paper_bgcolor=chart_paper, plot_bgcolor=chart_plot)
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
        st.info("📩 Parsed message(s) do not contain labels. Using metadata-only analysis for anomaly detection.")
else:
    st.info("Upload your email or chat log (CSV, MBOX, EML, MSG, JSON) to begin.")
