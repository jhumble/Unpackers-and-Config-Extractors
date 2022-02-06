# Dockerfile builds Speakeasy and Unpacker 
# Modified from Speakeasy Dockerfile - https://github.com/mandiant/speakeasy 

FROM python:3.8-alpine as base

# Use this base to build and install everything (this will bloat the size of this build image)
FROM base as builder
RUN apk add --no-cache gcc python3-dev make bash postgresql-dev libc-dev linux-headers

RUN which python3.8

RUN ln -sf /usr/local/bin/python3.8 /usr/local/bin/python
ADD ./requirements.txt /
RUN python -m pip install --upgrade pip && python -m pip install -r requirements.txt

FROM base
COPY --from=builder /usr/local/lib/python3.8/site-packages/ /usr/local/lib/python3.8/site-packages/

# Create an app user so we don't run as root
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# make the sandbox directory
RUN mkdir /sandbox

# Create the home directory
ENV APP_HOME=/app
RUN mkdir ${APP_HOME}
WORKDIR ${APP_HOME}

COPY ./speakeasy/speakeasy/ ${APP_HOME}/speakeasy
COPY ./speakeasy/setup.py ${APP_HOME}
COPY ./requirements.txt ${APP_HOME}
COPY ./speakeasy/MANIFEST.in ${APP_HOME}/speakeasy
COPY ./speakeasy/README.md ${APP_HOME}
COPY ./unpack.py ${APP_HOME}
COPY ./winfuncs.json ${APP_HOME}
COPY ./header_parser/ ${APP_HOME}/header_parser
COPY ./lib/ ${APP_HOME}/lib

# Chown all the files to the app user
RUN chown -R appuser:appgroup ${APP_HOME}
RUN chown -R appuser:appgroup /sandbox

RUN python ./setup.py install

# Change to the app user
USER appuser

CMD /bin/sh

