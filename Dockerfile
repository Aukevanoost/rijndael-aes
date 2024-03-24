FROM python:3.9

# Prepare workspace
WORKDIR /usr/rijndael
RUN apt-get install -y make gcc
RUN pip install pytest coverage

# Copy source-code
RUN mkdir ./dist
COPY ./src ./src
COPY ./tests ./tests
COPY ./Makefile .

# Compile code
RUN make
