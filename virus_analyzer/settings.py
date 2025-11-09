# ==========================================================
# START: RECOMMENDED - Load keys from .env file
# ==========================================================
# 
# Claude's notes included a .env file. This is the best practice.
# 1. Install it: pip install python-dotenv
# 2. Create a file named .env in the same folder as manage.py
# 3. Add your keys to that .env file (see example below)
# 4. Uncomment the lines below to use it.
#
# --- Example .env file ---
# SECRET_KEY=django-insecure-your-secret-key-change-this
# VIRUSTOTAL_API_KEY=fab79f9824e626a7d00c561e665c0f4114e7b7944600d93e76c40c1133baeb7b
# OTX_API_KEY=b9a58f6225e47a8c3df8ae68fd9a44a0e7b6611dc74b0ea46b3d00b3abb53131
# IPINFO_TOKEN=847f7f2396d348
# DEBUG=True
# -------------------------
#
# import os
# from dotenv import load_dotenv
# load_dotenv()
# ==========================================================
# END: RECOMMENDED
# ==========================================================


from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


# --- YOUR KEYS (KEPT FROM ORIGINAL) ---
# If using .env (recommended), replace these lines with:
# SECRET_KEY = os.getenv('SECRET_KEY')
# VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
# OTX_API_KEY = os.getenv('OTX_API_KEY')
# IPINFO_TOKEN = os.getenv('IPINFO_TOKEN')

SECRET_KEY = 'django-insecure-your-secret-key-change-this-in-production-at-least-50-characters-long-with-special-chars-123456789'
VIRUSTOTAL_API_KEY = 'fab79f9824e626a7d00c561e665c0f4114e7b7944600d93e76c40c1133baeb7b'
OTX_API_KEY = 'b9a58f6225e47a8c3df8ae68fd9a44a0e7b6611dc74b0ea46b3d00b3abb53131'
IPINFO_TOKEN = '847f7f2396d348'

# --- DEBUG & HOSTS ---
# If using .env, replace this with:
# DEBUG = os.getenv('DEBUG', 'False') == 'True'
DEBUG = True
ALLOWED_HOSTS = []


# --- MERGED APPLICATIONS ---
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.humanize',   # <-- Kept from your original
    
    # Third-party apps
    'channels',                 # <-- Added from Claude
    'rest_framework',           # <-- Added from Claude
    
    # Your apps
    'vt_analyzer',
]

# --- NEW: CUSTOM USER MODEL ---
AUTH_USER_MODEL = 'vt_analyzer.User' # <-- Added from Claude

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

# --- YOUR ORIGINAL PROJECT SETTINGS ---
ROOT_URLCONF = 'virus_analyzer.urls'
WSGI_APPLICATION = 'virus_analyzer.wsgi.application'

# --- NEW: CHANNELS CONFIGURATION (Corrected project name) ---
ASGI_APPLICATION = 'virus_analyzer.asgi.application'

# For development, use in-memory channel layer (no Redis needed):
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels.layers.InMemoryChannelLayer"
    }
}
# For production (requires Redis server):
# CHANNEL_LAYERS = {
#     'default': {
#         'BACKEND': 'channels_redis.core.RedisChannelLayer',
#         'CONFIG': {
#             "hosts": [('127.0.0.1', 6379)],
#         },
#     },
# }

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# --- YOUR ORIGINAL DATABASE (Good for development) ---
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',},
]

# --- YOUR ORIGINAL INTERNATIONALIZATION ---
LANGUAGE_CODE = 'fr-fr'
TIME_ZONE = 'Europe/Paris'
USE_I18N = True
USE_TZ = True


# --- MERGED: STATIC & MEDIA FILES ---
STATIC_URL = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

MEDIA_URL = '/media/'
MEDIA_ROOT = BASE_DIR / 'media'


DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


# --- NEW: AWS, EMAIL, LOGIN, SESSION, UPLOAD SETTINGS ---

# AWS Configuration (optional - can be configured in database)
AWS_ACCESS_KEY_ID = 'your-aws-access-key'         # <-- Add to .env
AWS_SECRET_ACCESS_KEY = 'your-aws-secret-key' # <-- Add to .env
AWS_DEFAULT_REGION = 'us-east-1'                  # <-- Add to .env

# Email Configuration (for notifications)
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'your-email@example.com'      # <-- Add to .env
EMAIL_HOST_PASSWORD = 'your-email-password'     # <-- Add to .env (Use App Password for Gmail)

# Login/Logout URLs
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/redirect_user/' 
LOGOUT_REDIRECT_URL = '/login/'

# Session Settings
SESSION_COOKIE_AGE = 3600  # 1 hour
SESSION_SAVE_EVERY_REQUEST = True

# File Upload Settings
FILE_UPLOAD_MAX_MEMORY_SIZE = 52428800  # 50MB
DATA_UPLOAD_MAX_MEMORY_SIZE = 52428800

# Celery Configuration (for async tasks)
# CELERY_BROKER_URL = 'redis://localhost:6379/0'
# CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'
# CELERY_ACCEPT_CONTENT = ['json']
# CELERY_TASK_SERIALIZER = 'json'
# CELERY_RESULT_SERIALIZER = 'json'


# --- REPLACED: LOGGING (More complete version from Claude) ---
# **NOTE: You must create the 'logs' directory: mkdir logs**
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': { # We are only keeping the 'console' handler
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['console'], # Only log to console
            'level': 'INFO',
            'propagate': True,
        },
        'vt_analyzer': {
            'handlers': ['console'], # Only log to console
            'level': 'DEBUG',
            'propagate': False,
        },
        'virustotal': {
            'handlers': ['console'], # Only log to console
            'level': 'ERROR',
            'propagate': False,
        },
    },
}