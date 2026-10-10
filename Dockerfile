FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# The app files stay owned by root, so the app can read them but not change them
COPY . .
# Run as an unprivileged user
RUN useradd --create-home --uid 10001 app
USER app
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
