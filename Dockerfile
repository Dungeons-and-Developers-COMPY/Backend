# Use official Python image
FROM python:3.10

# Set work directory
WORKDIR /my_app

# Copy dependencies
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy app files
COPY . .

# Run Flask app
CMD ["flask", "run", "--host=0.0.0.0"]
