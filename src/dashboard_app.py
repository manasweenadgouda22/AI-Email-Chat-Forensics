import streamlit as st
import pandas as pd
import plotly.express as px
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from data_cleaner import load_and_clean
from feature_engineer import extract_metadata_features
from threat_scoring import compute_metadata_score, compute_threat_score, label_risk

st.set_page_config(page_title="AI Email & Chat Forensics", layout="wide")
st.title("🔍 AI-Assisted Email & Chat Log Forensics")

uploaded = st.file_uploader("Upload CSV with at least: message, label, sender, timestamp, ip", type=["csv"])

if uploaded:
    df = load_and_clean(uploaded, text_col="message")
    st.subheader("Data Preview")
    st.dataframe(df.head(20))

    # Baseline NLP model (train on provided labeled data for demo)
    if "label" in df.columns:
        tfidf = TfidfVectorizer(stop_words="english", max_features=5000)
        X = tfidf.fit_transform(df["message"].astype(str))
        y = df["label"]
        model = LogisticRegression(max_iter=1000)
        model.fit(X, y)
        nlp_prob = model.predict_proba(X)[:, 1] if len(set(y)) == 2 else model.predict_proba(X).max(axis=1)

        # Metadata features
        df_feat = extract_metadata_features(df, sender_col="sender", ts_col="timestamp", ip_col="ip", msg_col="message")
        meta_score = compute_metadata_score(df_feat)

        # Threat score
        alpha = st.slider("Weight for NLP Probability (alpha)", 0.0, 1.0, 0.7, 0.05)
        threat = compute_threat_score(pd.Series(nlp_prob), meta_score, alpha=alpha)
        risk = label_risk(threat)

        out = df_feat.copy()
        out["nlp_prob"] = nlp_prob
        out["metadata_score"] = meta_score
        out["threat_score"] = threat
        out["risk"] = risk

        st.subheader("Threat Overview")
        fig = px.histogram(out, x="risk", title="Risk Distribution")
        st.plotly_chart(fig, use_container_width=True)

        st.subheader("Timeline View")
        if "timestamp" in out.columns:
            try:
                out_sorted = out.copy()
                out_sorted["timestamp"] = pd.to_datetime(out_sorted["timestamp"], errors="coerce")
                fig2 = px.scatter(out_sorted.sort_values("timestamp"), x="timestamp", y="threat_score",
                                  color="risk", hover_data=["sender","nlp_prob","metadata_score"])
                fig2.update_traces(mode="lines+markers")
                st.plotly_chart(fig2, use_container_width=True)
            except Exception as e:
                st.warning(f"Could not render timeline: {e}")

        st.subheader("Flagged Messages (High Risk)")
        st.dataframe(out[out["risk"]=="High"].head(50))

        # Download results
        st.download_button("Download Scored CSV",
                           data=out.to_csv(index=False).encode("utf-8"),
                           file_name="forensic_scored_results.csv",
                           mime="text/csv")
    else:
        st.warning("No 'label' column found. Please provide labeled data for demo training.")
else:
    st.info("Upload a CSV to begin. Example columns: message,label,sender,timestamp,ip")
