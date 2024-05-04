FROM python:3.11-slim-bullseye

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
ENV MYSQLCLIENT_CFLAGS "-I/usr/include/mysql"
ENV MYSQLCLIENT_LDFLAGS "-L/usr/lib/x86_64-linux-gnu -lmysqlclient"

RUN apt-get update && apt-get install -y \
    build-essential \
    default-libmysqlclient-dev \
    netcat

# Set the working directory in the container
WORKDIR /code

# Install pipenv
RUN pip install pipenv

# Copy Pipfile and Pipfile.lock to the container
COPY Pipfile Pipfile.lock ./

# Install dependencies
RUN pipenv install

# Copy the current directory contents into the container to working dir
COPY . .

WORKDIR /code/app