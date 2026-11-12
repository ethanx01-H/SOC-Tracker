FROM python:3.12-alpine

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && addgroup -S app && adduser -S -G app app
COPY . .
RUN mkdir -p /app/data && chown -R app:app /app

EXPOSE 8080
USER app
ENTRYPOINT ["/app/docker-entrypoint.sh"]
