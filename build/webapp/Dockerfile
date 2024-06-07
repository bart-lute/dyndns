FROM python:3.12-alpine
WORKDIR /usr/local/app

EXPOSE 5000

COPY requirements.txt ./
COPY main.py ./
COPY .env-docker ./.env

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "main.py"]