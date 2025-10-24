import pandas as pd
import numpy as np

def compute_metadata_score(df: pd.DataFrame) -> pd.Series:
    # simple weighted metadata score
    w_off = 0.3
    w_key = 0.5
    w_ext = 0.2
    meta = (w_off*df.get("off_hours_flag", 0).astype(float) +
            w_key*df.get("keyword_flag", 0).astype(float) +
            w_ext*df.get("external_ip_flag", 0).astype(float))
    return (meta - meta.min()) / (meta.max() - meta.min() + 1e-9)

def compute_threat_score(nlp_prob: pd.Series, metadata_score: pd.Series, alpha: float = 0.7) -> pd.Series:
    alpha = float(alpha)
    return alpha * nlp_prob.astype(float) + (1 - alpha) * metadata_score.astype(float)

def label_risk(threat_score: pd.Series) -> pd.Series:
    bins = [-1, 0.33, 0.66, 1.0]
    labels = ["Low","Medium","High"]
    return pd.cut(threat_score, bins=bins, labels=labels)
