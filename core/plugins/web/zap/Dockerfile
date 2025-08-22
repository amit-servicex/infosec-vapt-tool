FROM zaproxy/zap-stable
USER root
RUN apt-get update && apt-get install -y python3 ca-certificates && \
    ln -sf /usr/bin/python3 /usr/bin/python && rm -rf /var/lib/apt/lists/*
USER zap
WORKDIR /app
COPY --chown=zap:zap main.py /app/main.py
ENTRYPOINT ["python3","/app/main.py"]
