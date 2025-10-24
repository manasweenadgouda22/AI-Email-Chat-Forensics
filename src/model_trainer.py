import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report

def train_baseline(df: pd.DataFrame, text_col: str = "message", label_col: str = "label"):
    X_train, X_test, y_train, y_test = train_test_split(df[text_col].astype(str), df[label_col], test_size=0.2, random_state=42, stratify=df[label_col])
    vec = TfidfVectorizer(stop_words="english", max_features=5000)
    Xtr = vec.fit_transform(X_train)
    Xte = vec.transform(X_test)
    model = LogisticRegression(max_iter=1000, n_jobs=None)
    model.fit(Xtr, y_train)
    preds = model.predict(Xte)
    report = classification_report(y_test, preds, output_dict=True)
    return {"vectorizer": vec, "model": model, "report": report}
