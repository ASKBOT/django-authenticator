this is a based on a forked version of django-authopenid module
developed for the Askbot forum project.

This module is experimental

Settings
========
These settings can be added to your settings.py file.
or controlled via module located at the path stored in the string:
EXTRA_SETTINGS_MODULE (optional).

This extra settings module may be livesettings or something similar,
but it needs to have the same interface as django's builtin settings
module.

ALLOW_ACCOUNT_RECOVERY_BY_EMAIL - boolean
ALLOW_ADD_REMOVE_LOGIN_METHODS - boolean
APP_SHORT_NAME - brief title of the app
APP_URL - base url of the app
ASKBOT_CUSTOM_AUTH_MODULE - auth plugin module
EMAIL_VALIDATION

FACEBOOK_KEY - note Facebook is currently not working
FACEBOOK_SECRET

IDENTICA_KEY
IDENTICA_SECRET
LINKEDIN_KEY
LINKEDIN_SECRET
TWITTER_KEY
TWITTER_SECRET

PASSWORD_MIN_LENGTH
USE_LDAP_FOR_PASSWORD_LOGIN - Boolean
LDAP_PROVIDER_NAME
LDAP_URL

LOCAL_LOGIN_ICON - url to local login icon

OPENID_DISALLOW_INAMES
OPENID_TRUST_ROOT

USE_RECAPTCHA - Boolean
RECAPTCHA_KEY
RECAPTCHA_SECRET
SIGNIN_ALWAYS_SHOW_LOCAL_LOGIN - always show password form
SIGNIN_xyz_ENABLED, where xyz is in the list of avaliable providers in upper case
