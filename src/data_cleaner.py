import pandas as pd
import re

# ----------------------------------------------------
# Utility: Clean text fields
# ----------------------------------------------------
def clean_text(s: str) -> str:
    if not isinstance(s, str):
        return ""
    s = s.replace("\n", " ").strip()
    s = re.sub(r"\s+", " ", s)
    return s


# ----------------------------------------------------
# Main cleaning function
# ----------------------------------------------------
def load_and_clean(df, text_col="message"):
    """
    Cleans a DataFrame or file path containing email/chat data.
    Ensures consistent columns: message, label, sender, timestamp, ip
    """

    # Allow file path or DataFrame input
    if not isinstance(df, pd.DataFrame):
        df = pd.read_csv(df)

    # --- Normalize column names ---
    df.columns = [c.strip().lower() for c in df.columns]

    # --- Ensure required columns exist ---
    for col in ["message", "label", "sender", "timestamp", "ip"]:
        if col not in df.columns:
            df[col] = None

    # --- Clean message text ---
    if text_col in df.columns:
        df[text_col] = df[text_col].astype(str).map(clean_text)

    # --- Drop duplicates and blanks ---
    df = df.dropna(subset=["message"])
    df = df.drop_duplicates(subset=["message"])

    # --- Reset index for consistency ---
    df = df.reset_index(drop=True)

    return df
