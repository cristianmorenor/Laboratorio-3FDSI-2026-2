FROM python:3.9-slim
WORKDIR /srv/app
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 5000
# Corre como root a proposito (hallazgo para Trivy/Hadolint)
CMD ["python", "app.py"]
