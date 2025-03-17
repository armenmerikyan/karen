from __future__ import absolute_import, unicode_literals
import os
from pathlib import Path
import random
import string

CORS_ALLOW_ALL_ORIGINS = True  # Don't use in production

SITE_ID = 1

def generate_secret_key(length=50):
    """Generates a random secret key."""
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

HTTP_TIMEOUT = 1800

APPEND_SLASH = False
# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
 
SECRET_KEY =  os.environ.get('D_SECRET_KEY')
SECRET_KEY = os.environ.get('D_SECRET_KEY', generate_secret_key())
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = os.environ.get('D_SOCIAL_AUTH_GOOGLE_OAUTH2_KEY')
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = os.environ.get('D_SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET')
SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE = ['email', 'profile']

SOCIAL_AUTH_GOOGLE_OAUTH2_AUTH_EXTRA_ARGUMENTS = {
    'access_type': 'offline',
    'prompt': 'consent',
}

SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.auth_allowed',
    'social_core.pipeline.social_auth.social_user',
    'social_core.pipeline.user.get_username',
    'store.pipeline.get_email',  # Add the custom function here
    'store.pipeline.associate_by_email',
    'social_core.pipeline.user.create_user',
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'store.pipeline.user_details',
)


# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = os.getenv('ALLOWED_HOSTS', '127.0.0.1,localhost').split(',')
CSRF_TRUSTED_ORIGINS = os.getenv('CSRF_TRUSTED_ORIGINS', 'http://localhost').split(',')

print(f"ALLOWED_HOSTS: {ALLOWED_HOSTS}")
print(f"CSRF_TRUSTED_ORIGINS: {CSRF_TRUSTED_ORIGINS}") 

SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')


X_CSRFTOKEN_HEADER = 'X-CSRFTOKEN'
X_CSRF_TOKEN_HEADER = 'X-CSRF-TOKEN'

# Application definition
 
ACCOUNT_EMAIL_VERIFICATION = "none"
LOGOUT_REDIRECT_URL = "/"


INSTALLED_APPS = [
    'django.contrib.sites', 
    'allauth',
    'allauth.account',
    'allauth.socialaccount',
    'allauth.socialaccount.providers.google',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'store',
    'corsheaders',
    'social_django',
    'rest_framework',
    'rest_framework.authtoken',
    'drf_spectacular',
    'oauth2_provider',
]


AUTHENTICATION_BACKENDS = (
    'allauth.account.auth_backends.AuthenticationBackend',
    'social_core.backends.google.GoogleOAuth2',
    'django.contrib.auth.backends.ModelBackend',  
)

AUTHENTICATION_BACKENDS = (
    'allauth.account.auth_backends.AuthenticationBackend',
    'social_core.backends.google.GoogleOAuth2',
) 

MIDDLEWARE = [ 
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'corsheaders.middleware.CorsMiddleware',
    # other middleware
    'django.middleware.security.SecurityMiddleware',

    # Add AccountMiddleware from allauth
    'allauth.account.middleware.AccountMiddleware', 
]

REST_FRAMEWORK = {
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication', 
    ),    
    'DEFAULT_PERMISSION_CLASSES': [ 
        'rest_framework.permissions.IsAuthenticated',
    ],
}
from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),  # Access token validity
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),    # Refresh token validity
} 

SPECTACULAR_SETTINGS = {
    'SCHEMA_VERSION': '3.1.0',
    'SECURITY': [],  # explicitly disable security schemes
    'SERVE_PERMISSIONS': ['rest_framework.permissions.AllowAny'],  # allow open access

    'COMPONENT_SPLIT_REQUEST': True,
    'DEFAULT_GENERATOR_CLASS': 'drf_spectacular.generators.SchemaGenerator',
    "TITLE": "Gigahard API",
    "DESCRIPTION": "OpenAPI schema for Business MCP integration",
    "VERSION": "1.0.0", 
    "SERVE_INCLUDE_SCHEMA": False,
    "SERVE_PERMISSIONS": [],
    "SERVERS": [{"url": "https://gigahard.ai"}],  
    "COMPONENT_SPLIT_RESPONSE": True,
    'SECURITY': [
        {'jwtAuth': []}  # Use only one method in OpenAPI docs
    ]
} 

ROOT_URLCONF = 'website.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR, 'templates')],
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

WSGI_APPLICATION = 'website.wsgi.application'


# Database LOCAL MYSQL INSTNCE DEPLOYMENT
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases



## RDS Deployment
# AWS RDS settings

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# USED FOR Heroku deployment
'''
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': os.environ['CLEARDB_DATABASE_NAME'],
        'USER': os.environ['CLEARDB_DATABASE_USER'],
        'PASSWORD': os.environ['CLEARDB_DATABASE_PASSWORD'],
        'HOST': os.environ['CLEARDB_DATABASE_HOST'],
        'PORT': os.environ['CLEARDB_DATABASE_PORT'],
    }
}
'''
'''
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': os.environ['CLEARDB_DATABASE_NAME'],
        'USER': os.environ['CLEARDB_DATABASE_USER'],
        'PASSWORD': os.environ['CLEARDB_DATABASE_PASSWORD'],
        'HOST': os.environ['CLEARDB_DATABASE_HOST'],
        'PORT': os.environ['CLEARDB_DATABASE_PORT'],
    }
}

'''
# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/
 


STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static'),
]

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
AUTH_USER_MODEL="store.User"

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': '/tmp/file.log',
        },
    },
    'loggers': {
        'django': {
            'handlers': ['file'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
}


  

X_FRAME_OPTIONS = 'SAMEORIGIN'

ACCOUNT_EMAIL_REQUIRED = True
ACCOUNT_EMAIL_VERIFICATION = "optional"  # Options: "none", "optional", "mandatory"
ACCOUNT_AUTHENTICATION_METHOD = "username"  # Use email as the login identifier
ACCOUNT_USERNAME_REQUIRED = False

EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.sendgrid.net"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = "apikey"  # This is the literal string 'apikey'
EMAIL_HOST_PASSWORD = os.environ.get('EMAIL_HOST_PASSWORD')  # Replace with your SendGrid API Key
DEFAULT_FROM_EMAIL = os.environ.get('DEFAULT_FROM_EMAIL')


SOCIALACCOUNT_PROVIDERS = {
    'google': {
        'APP': {
            'client_id': os.environ.get('GOOGLE_OAUTH_CLIENT_ID'),
            'secret': os.environ.get('GOOGLE_OAUTH_CLIENT_SECRET'),
            'key': ''
        }
    }
}
