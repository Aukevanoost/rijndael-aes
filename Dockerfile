FROM python:3.9-slim

# Prepare workspace
WORKDIR /usr/rijndael
RUN apt-get update && apt-get install -y make gcc 
RUN pip install pytest coverage

# clear cache
RUN rm -rf /var/lib/apt/lists/* 

# Copy source-code
RUN mkdir ./dist
COPY ./src ./src
COPY ./tests ./tests
COPY ./Makefile .

# Compile code
RUN make
