FROM python:3.10-slim

RUN pip3 install flask
RUN pip3 install flask_sqlalchemy
RUN pip3 install flask_login
RUN pip3 install werkzeug

WORKDIR /opt/app

COPY . /opt/app/

CMD [ "python", "./app.py" ]