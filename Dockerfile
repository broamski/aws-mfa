FROM python:3-alpine

WORKDIR /usr/src/app

RUN apk add --update --no-cache make \
  gcc \
  gcc-doc \
  linux-headers \
  libc-dev \
  libffi-dev \
  openssl-dev

RUN pip install aws-mfa

ENTRYPOINT ["aws-mfa"]
