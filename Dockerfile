# Pinned to a digest so a re-pushed tag can't change the image; Dependabot proposes updates.
FROM python:3.13-slim@sha256:57b29a7c050c4e679e4bea572e14b3965cf4b5839de2da49d55e49ffc4024f39
WORKDIR /app
COPY requirements.txt .
# pip 26.2.2 or later: older pips keep trusting the revoked eMudhra/emSign certificates (https://discuss.python.org/t/109576).
# The wheel's SHA-256 is pinned, so it's verified even if this step's own connection isn't.
RUN pip install --no-cache-dir "https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
RUN pip install --no-cache-dir -r requirements.txt
# The app files stay owned by root, so the app can read them but not change them
COPY . .
# Run as an unprivileged user
RUN useradd --create-home --uid 10001 app
USER app
EXPOSE 8501
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
