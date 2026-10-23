# Pinned to a digest so a re-pushed tag can't change the image; Dependabot proposes updates.
FROM python:3.13-slim@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39
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
