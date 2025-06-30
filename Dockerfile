# Use official Python image
FROM python:3.10

# Set work directory (make sure it matches your volume mount)
WORKDIR /app

# Copy dependencies
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy app files
COPY . .

# Set environment variables to enable Flask auto reload
ENV FLASK_APP=my_app
ENV FLASK_ENV=development

# Run Flask app with reload enabled
CMD ["flask", "run", "--host=0.0.0.0", "--reload"]
