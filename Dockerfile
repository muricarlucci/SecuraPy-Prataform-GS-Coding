FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN python ml/treinar.py

EXPOSE 5000 9999

CMD ["python", "api/app.py"]
