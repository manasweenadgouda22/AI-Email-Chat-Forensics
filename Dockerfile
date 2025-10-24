FROM python:3.10-slim

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

COPY src /app/src
COPY data /app/data
EXPOSE 8501

CMD ["streamlit", "run", "src/dashboard_app.py", "--server.port=8501", "--server.address=0.0.0.0"]
