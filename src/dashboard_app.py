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
# Page Setup & Styling
# ----------------------------------------------------
st.set_page_config(page_title="AI Email & Chat Forensics", layout="wide")

# Custom CSS theme — modern, forensic look
st.markdown("""
<style>
/* ---------- Global Layout ---------- */
[data-testid="stAppViewContainer"] {
    background: linear-gradient(180deg, #0a192f 0%, #112240 100%);
    color: #e6f1ff;
    font-family: 'Inter', sans-serif;
    padding: 1rem 2rem;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: #09192d;
    border-right: 1px solid rgba(255, 255, 255, 0.1);
}

/* Main Card Container */
.main-card {
    background: rgba(255,255,255,0.05);
    border: 1px solid rgba(255,255,255,0.15);
    border-radius: 16px;
    padding: 25px;
    box-shadow: 0 4px 20px rgba(0,0,0,0.25);
}

/* Headings */
h1, h2, h3 {
    color: #64ffda;
    font-weight: 700;
}
h1 {
    font-size: 2.4rem;
    text-shadow: 0 0 10px rgba(100,255,218,0.2);
}
h2 {
    border-left: 4px solid #64ffda;
    padding-left: 10px;
}

/* Tables */
.stDataFrame table {
    border-radius: 8px;
    border: 1px solid rgba(255,255,255,0.15);
    background-color: rgba(255,255,255,0.04);
    color: #e6f1ff;
}

/* Sliders */
.stSlider {
    background: rgba(255,255,255,0.05);
    border-radius: 10px;
    border: 1px solid rgba(255,255,255,0.1);
}

/* Plotly area */
.plotly {
    background-color: rgba(255,255,255,0.05) !important;
    border-radius: 12px;
    padding: 10px;
}

/* Buttons */
button[kind="primary"] {
    background-color: #64ffda !important;
    color: #0a192f !important;
    border: none !important;
    font-weight: 700 !important;
    border-radius: 8px !important;
    transition: all 0.3s ease;
}
button[kind="primary"]:hover {
    background-color: #5de0c0 !important;
    transform: translateY(-1px);
}

/* Info / Warning Boxes */
[data-baseweb="toast"] {
    border: 1px solid rgba(100,255,218,0.3);
    border-radius: 10px;
}
</style>
""", unsafe_allow_html=True)

# ----------------------------------------------------
# Header
# ----------------------------------------------------
st.markdown('<div class="main-card">', unsafe_allow_html=True)
st.title("🔍 AI-Assisted Email & Chat Log Forensics")
st.markdown("Analyze digital communications using NLP & metadata correlation to flag potentially risky or malicious behavior.")
st.write("✅ Running latest version — supports JSON, MBOX, EML, MSG, and CSV.")
st.markdown('</div>', unsafe_allow_html=True)

# ----------------------------------------------------
# File Upload Section
# ----------------------------------------------------
st.markdown('<div class="main-card">', unsafe_allow_html=True)
uploaded = st.file_uploader(
    "📂 Upload your email/chat data file (Supported: CSV, MBOX, EML, MSG, JSON)",
    type=["csv", "mbox", "eml", "msg", "json"]
)

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

    # ------------------------------------------------
    # Data Cleaning
    # ------------------------------------------------
    df = load_and_clean(df, text_col="message")

    # ------------------------------------------------
    # NLP & Threat Scoring
    # ------------------------------------------------
    if "label" in df.columns:
        st.subheader("Model Training & Threat Scoring")

        # Train baseline NLP model
        tfidf = TfidfVectorizer(stop_words="english", max_features=5000)
        X = tfidf.fit_transform(df["message"].astype(str))
        y = df["label"]
        model = LogisticRegression(max_iter=1000)
        model.fit(X, y)

        # Probabilities
        nlp_prob = model.predict_proba(X)[:, 1] if len(set(y)) == 2 else model.predict_proba(X).max(axis=1)

        # Metadata + Threat scoring
        df_feat = extract_metadata_features(df, sender_col="sender",
                                            ts_col="timestamp", ip_col="ip",
                                            msg_col="message")
        meta_score = compute_metadata_score(df_feat)

        st.markdown("#### Weight Adjustment")
        alpha = st.slider("Weight for NLP Probability (α)", 0.0, 1.0, 0.7, 0.05)
        threat = compute_threat_score(pd.Series(nlp_prob), meta_score, alpha=alpha)
        risk = label_risk(threat)

        # Merge results
        out = df_feat.copy()
        out["nlp_prob"] = nlp_prob
        out["metadata_score"] = meta_score
        out["threat_score"] = threat
        out["risk"] = risk

        # ------------------------------------------------
        # Visualization Section
        # ------------------------------------------------
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

        # ------------------------------------------------
        # Flagged Messages & Export
        # ------------------------------------------------
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
st.markdown('</div>', unsafe_allow_html=True)
