# Aucune dépendance (bibliothèque standard seule) → build sans réseau, image légère.
FROM python:3.11-alpine
WORKDIR /app
COPY app.py .
EXPOSE 5000
CMD ["python", "app.py"]
