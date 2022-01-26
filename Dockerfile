FROM python:3.8.5-alpine

RUN pip install --upgrade pip

RUN adduser -D myuser
USER myuser
WORKDIR /home/myuser

ENV PATH="/home/myuser/.local/bin:${PATH}"
COPY --chown=myuser:myuser src /home/myuser/src
RUN pip install --no-cache-dir --user -r /home/myuser/src/requirements.txt

COPY --chown=myuser:myuser . .

EXPOSE 8080
WORKDIR /home/myuser/src
ENTRYPOINT ["python","webapp.py"]
