# Define variables for paths
BACKEND_DIR := .
APP_DIR := $(BACKEND_DIR)/app

# Define commands with paths
PIPENV_RUN := pipenv run
BLACK_CMD := $(PIPENV_RUN) black $(BACKEND_DIR) --exclude='migrations' --skip-string-normalization
ISORT_CMD := $(PIPENV_RUN) isort $(APP_DIR)/**/* --filter-files --profile black
PYLINT_CMD := $(PIPENV_RUN) pylint $(APP_DIR) --load-plugins pylint_django --django-settings-module=app
GUNICORN_CMD := $(PIPENV_RUN) gunicorn app.wsgi -c $(BACKEND_DIR)/../gunicorn_config.py --env DJANGO_DEVELOPMENT=true --reload

# Backend tasks
check-format:
	$(BLACK_CMD) --check
	exit $$?

makemigrations:
	cd $(APP_DIR) && $(PIPENV_RUN) python manage.py makemigrations

migrate:
	cd $(APP_DIR) && $(PIPENV_RUN) python manage.py migrate

format:
	$(BLACK_CMD)

check-import-order:
	$(ISORT_CMD) -c

import-order:
	$(ISORT_CMD)

check:
	$(MAKE) check-format check-import-order lint

lint:
	$(PYLINT_CMD)

run-dev:
	cd $(APP_DIR) && DJANGO_DEVELOPMENT=true $(GUNICORN_CMD)

run-production:
	cd $(APP_DIR) && DJANGO_DEVELOPMENT=false $(GUNICORN_CMD)
