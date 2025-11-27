# Use a Python 3.11 slim image as the base
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Create the temporary directory for the SQLite database and set permissions
RUN mkdir -p /tmp/db && chmod -R 777 /tmp/db

# Copy the core requirements file and install dependencies
# We copy it separately to leverage Docker's caching for dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create the /app/api directory for FastAPI's main.py and index.html,
# which will be mounted individually.
RUN mkdir -p /app/api

# Set environment variable for PYTHONPATH to include the project root
# This helps Python find modules like 'utils' and 'rules'
ENV PYTHONPATH=/app

# Expose the port FastAPI runs on
EXPOSE 8000

# Command to run the FastAPI application
# Ensure main.py is directly executable or use uvicorn to run it
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
