FROM python:3.11-slim
WORKDIR /app
COPY main.py /app/main.py
# (Optional) If you want Jinja2 templated report, add your templates + install Jinja2:
# COPY ../writers/html_writer.py /app/html_writer.py
# COPY ../templates /app/templates
# RUN pip install Jinja2
ENTRYPOINT ["python","/app/main.py"]
