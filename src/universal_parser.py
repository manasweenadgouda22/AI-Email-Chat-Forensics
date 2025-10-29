import pandas as pd
import mailbox, email, json
from email import policy

def parse_csv(file):
    """Parse CSV files."""
    return pd.read_csv(file)

def parse_mbox(file):
    """Parse Gmail .mbox exports."""
    mbox = mailbox.mbox(file)
    data = []
    for msg in mbox:
        data.append({
            "sender": msg["from"],
            "receiver": msg["to"],
            "subject": msg["subject"],
            "message": msg.get_payload(),
            "timestamp": msg["date"],
            "ip": None
        })
    return pd.DataFrame(data)

def parse_eml(file):
    """Parse individual .eml email files."""
    msg = email.message_from_bytes(file.read(), policy=policy.default)
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_content()
    else:
        body = msg.get_content()
    return pd.DataFrame([{
        "sender": msg["from"],
        "receiver": msg["to"],
        "subject": msg["subject"],
        "message": body,
        "timestamp": msg["date"],
        "ip": None
    }])

def parse_msg(file):
    """Parse Outlook .msg files."""
    import extract_msg
    msg = extract_msg.Message(file)
    return pd.DataFrame([{
        "sender": msg.sender,
        "receiver": msg.to,
        "subject": msg.subject,
        "message": msg.body,
        "timestamp": msg.date,
        "ip": None
    }])

def parse_json(file):
    """Parse JSON chat exports (Slack, Teams, etc.)."""
    content = json.load(file)
    if isinstance(content, list):
        return pd.DataFrame(content)
    else:
        return pd.DataFrame([content])

def parse_file(file, extension):
    """Main entry: route to correct parser based on file extension."""
    if extension == ".csv":
        return parse_csv(file)
    elif extension == ".mbox":
        return parse_mbox(file)
    elif extension == ".eml":
        return parse_eml(file)
    elif extension == ".msg":
        return parse_msg(file)
    elif extension == ".json":
        return parse_json(file)
    else:
        raise ValueError(f"Unsupported file type: {extension}")
