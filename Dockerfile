FROM python:3.10.2-alpine

ARG USERNAME=myuser
ARG USERHOME=/home/$USERNAME

RUN pip install --upgrade pip

RUN addgroup $USERNAME
RUN adduser -u 1000 -SH -G $USERNAME $USERNAME
RUN mkdir -p $USERHOME
RUN chown -R $USERNAME:$USERNAME $USERHOME

USER $USERNAME
WORKDIR $USERHOME

ENV PATH="/home/myuser/.local/bin:${PATH}"
COPY --chown=myuser:myuser src /home/myuser/src
RUN pip install --no-cache-dir --user -r /home/myuser/src/requirements.txt

COPY --chown=myuser:myuser . .

EXPOSE 8080
WORKDIR /home/myuser/src
ENTRYPOINT ["python","webapp.py"]
