# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy all project files into the container
COPY ./app /app

# Copy requirements.txt into container (make sure it’s in ./webpy)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose port
EXPOSE 8090

# No buffering for logs
ENV PYTHONUNBUFFERED=1

# Start the app
CMD ["python", "app.py"]
