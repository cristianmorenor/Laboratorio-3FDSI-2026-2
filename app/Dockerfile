FROM python:3.12-slim
WORKDIR /srv/app
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /srv/app netops
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=netops:netops . .
USER netops
ENV HOST=0.0.0.0 PORT=5000
EXPOSE 5000
HEALTHCHECK CMD python -c "import urllib.request as u; u.urlopen('http://127.0.0.1:5000/health')"
CMD ["sh", "-c", "python -c 'import app; app.init_db()' && exec gunicorn -b 0.0.0.0:5000 -w 2 app:app"]
