import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
import os

# Internal modules
from src.universal_parser import parse_file
from data_cleaner import load_and_clean
from feature_engineer import extract_metadata_features
from threat_scoring import compute_metadata_score, compute_threat_score, label_risk

# ----------------------------------------------------
# Page Setup & Styling
# ----------------------------------------------------
st.set_page_config(page_title="AI Email & Chat Forensics", layout="wide")
st.markdown(
    """
    <style>
    [data-testid="stAppViewContainer"] {
        background: linear-gradient(180deg, #ffffff 0%, #f9fafb 100%);
        color: #1e1e1e;
        font-family: "Inter", sans-serif;
    }
    [data-testid="stSidebar"] { background-color: #f3f4f6; }
    h1, h2, h3 { color: #0b3954; font-weight: 700; }
    .stDataFrame table { border-radius: 10px; border: 1px solid #e5e7eb; }
    .stSlider { background: #ffffff; border-radius: 10px; }
    .plotly { background-color: #ffffff !important; border-radius: 8px; padding: 10px; }
    </style>
    """,
    unsafe_allow_html=True
)

# ----------------------------------------------------
# Header
# ----------------------------------------------------
st.title("🔍 AI-Assisted Email & Chat Log Forensics")
st.markdown("Analyze email and chat communications using NLP + metadata correlation to flag risky behavior.")

# ----------------------------------------------------
# File Upload Section
# ----------------------------------------------------
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
    # NLP & Threat Scoring Section
    # ------------------------------------------------
    if "label" in df.columns:
        st.subheader("Model Training & Threat Scoring")

        # Train baseline NLP model (TF-IDF + Logistic Regression)
        tfidf = TfidfVectorizer(stop_words="english", max_features=5000)
        X = tfidf.fit_transform(df["message"].astype(str))
        y = df["label"]
        model = LogisticRegression(max_iter=1000)
        model.fit(X, y)

        # NLP probabilities
        if len(set(y)) == 2:
            nlp_prob = model.predict_proba(X)[:, 1]
        else:
            nlp_prob = model.predict_proba(X).max(axis=1)

        # Metadata features
        df_feat = extract_metadata_features(df, sender_col="sender",
                                            ts_col="timestamp", ip_col="ip",
                                            msg_col="message")
        meta_score = compute_metadata_score(df_feat)

        # Combine scores
        st.markdown("#### Weight Adjustment")
        alpha = st.slider("Weight for NLP Probability (α)", 0.0, 1.0, 0.7, 0.05)
        threat = compute_threat_score(pd.Series(nlp_prob), meta_score, alpha=alpha)
        risk = label_risk(threat)

        # Combine results
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
