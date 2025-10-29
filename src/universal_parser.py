import pandas as pd
import mailbox
import email
import extract_msg
import json
from io import BytesIO, StringIO


def parse_file(uploaded_file, ext):
    """
    Parse uploaded file and return a unified pandas DataFrame.
    Handles CSV, JSON, EML, MSG, and MBOX formats.
    """

    ext = ext.lower()
    messages = []

    # -------------------------------
    # CSV
    # -------------------------------
    if ext == ".csv":
        return pd.read_csv(uploaded_file)

    # -------------------------------
    # JSON
    # -------------------------------
    elif ext == ".json":
        try:
            return pd.read_json(uploaded_file)
        except Exception:
            uploaded_file.seek(0)
            data = json.load(uploaded_file)
            return pd.DataFrame(data)

    # -------------------------------
    # EML
    # -------------------------------
    elif ext == ".eml":
        raw_bytes = uploaded_file.read()
        msg = email.message_from_bytes(raw_bytes)

        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    body += part.get_payload(decode=True).decode(errors="ignore")
        else:
            body = msg.get_payload(decode=True).decode(errors="ignore")

        return pd.DataFrame([{
            "sender": msg.get("From", ""),
            "receiver": msg.get("To", ""),
            "subject": msg.get("Subject", ""),
            "message": body.strip(),
            "timestamp": msg.get("Date", None),
            "ip": None,
            "label": "Unlabeled"
        }])

    # -------------------------------
    # MSG (Outlook format)
    # -------------------------------
    elif ext == ".msg":
        try:
            msg = extract_msg.Message(uploaded_file)
            return pd.DataFrame([{
                "sender": msg.sender,
                "receiver": msg.to,
                "subject": msg.subject,
                "message": msg.body.strip(),
                "timestamp": msg.date,
                "ip": None,
                "label": "Unlabeled"
            }])
        except Exception as e:
            raise ValueError(f"Failed to parse MSG file: {e}")

    # -------------------------------
    # MBOX
    # -------------------------------
    elif ext == ".mbox":
        # Convert uploaded file into mailbox.mbox readable form
        uploaded_file.seek(0)
        mbox_data = uploaded_file.read()
        temp_path = "/tmp/temp_mbox.mbox"
        with open(temp_path, "wb") as f:
            f.write(mbox_data)

        mbox = mailbox.mbox(temp_path)
        for msg in mbox:
            try:
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            body += part.get_payload(decode=True).decode(errors="ignore")
                else:
                    body = msg.get_payload(decode=True).decode(errors="ignore")

                messages.append({
                    "sender": msg.get("from", ""),
                    "receiver": msg.get("to", ""),
                    "subject": msg.get("subject", ""),
                    "message": body.strip(),
                    "timestamp": msg.get("date", None),
                    "ip": None,
                    "label": "Unlabeled"
                })
            except Exception:
                continue
        return pd.DataFrame(messages)

    # -------------------------------
    # Unsupported
    # -------------------------------
    else:
        raise ValueError(f"Unsupported file format: {ext}")
