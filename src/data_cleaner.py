import pandas as pd
import re

def clean_text(s: str) -> str:
    if not isinstance(s, str):
        return ""
    s = s.replace("\n", " ").strip()
    s = re.sub(r"\s+", " ", s)
    return s

def load_and_clean(path: str, text_col: str = "message") -> pd.DataFrame:
    df = pd.read_csv(path)
    if text_col in df.columns:
        df[text_col] = df[text_col].astype(str).map(clean_text)
    return df
