# Use an official Python runtime as a parent image
FROM python:3.10-slim-buster

# Set environment variables
ENV PYTHONUNBUFFERED 1
ENV DJANGO_SETTINGS_MODULE merchantonboardingservice.settings_dev

# Set the working directory
WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*
RUN pip install psycopg2-binary
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy the project files into the container
COPY . /app/

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Expose the port for the application
EXPOSE 8002

# Set up Nginx on the container
RUN apt-get update && apt-get install -y nginx

RUN chmod -R +w /app/onboarding/migrations

# Start the application
CMD ["/entrypoint.sh"]


