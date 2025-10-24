import pandas as pd
import tldextract
from datetime import datetime

PHISH_KEYWORDS = {"urgent","invoice","password","verify","reset","immediately","gift card","wire","otp","click","link"}

def extract_metadata_features(df: pd.DataFrame,
                              sender_col: str = "sender",
                              ts_col: str = "timestamp",
                              ip_col: str = "ip",
                              msg_col: str = "message") -> pd.DataFrame:
    out = df.copy()

    # domain parts
    def get_domain(s):
        if not isinstance(s, str): return ""
        ext = tldextract.extract(s.split("@")[-1] if "@" in s else s)
        dom = ".".join([p for p in [ext.domain, ext.suffix] if p])
        return dom.lower()

    out["sender_domain"] = out.get(sender_col, "").astype(str).map(get_domain)

    # after-hours comms flag (22:00–06:00)
    def off_hours(ts):
        try:
            t = datetime.fromisoformat(str(ts).replace("Z",""))
            return int(t.hour >= 22 or t.hour <= 6)
        except Exception:
            return 0
    out["off_hours_flag"] = out.get(ts_col, "").map(off_hours)

    # keyword hits
    def keyword_hits(s):
        s = str(s).lower()
        return int(any(k in s for k in PHISH_KEYWORDS))
    out["keyword_flag"] = out.get(msg_col, "").map(keyword_hits)

    # simple ip external flag (private ranges not external)
    def external_ip(ip):
        ip = str(ip)
        return int(not (ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.")))
    out["external_ip_flag"] = out.get(ip_col, "").map(external_ip)

    return out
