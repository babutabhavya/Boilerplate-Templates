import os

# Set the Django settings module for Gunicorn
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "app.settings")

# Set up log directory for Gunicorn logs
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gunicorn_logs")

if not os.path.exists(log_dir):
    os.makedirs(log_dir)

bind = "0.0.0.0:8000"
workers = 5
max_requests = 1000
timeout = 600
