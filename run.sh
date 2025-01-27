#!/bin/bash

# Activate the virtual environment
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Uncomment for Windows

# Export environment variables for Flask
export FLASK_APP=app.py
export FLASK_ENV=development  # Set to 'production' for deployment

# Start the Flask application
flask run --host=127.0.0.1 --port=5000
