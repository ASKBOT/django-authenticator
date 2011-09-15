"""setup routine for ``django_authenticator``.
Uses setuptools.
"""
import ez_setup
ez_setup.use_setuptools()
from setuptools import setup, find_packages

#NOTE: if you want to develop authenticator
#you might want to install django-debug-toolbar as well

INSTALL_REQUIRES = [
    'django-extra-form-fields',
    'django-registration',
    'import-utils',
    'multi-registry',
    'South',
    'oauth2',
    'python-openid',
    'python-wordpress-xmlrpc',
]

import django_authenticator

setup(
    name = "django-authenticator",
    version = django_authenticator.__version__,
    description = 'authentication client for django',
    packages = find_packages(),
    author = 'Evgeny.Fadeev',
    author_email = 'evgeny.fadeev@gmail.com',
    license = 'GPLv3',
    keywords = 'authentication, oauth, openid',
    entry_points = {
        'console_scripts' : [
            'startforum = authenticator.deployment:startforum',
        ]
    },
    url = '',
    include_package_data = True,
    install_requires = INSTALL_REQUIRES,
    classifiers = [
        'Development Status :: 2 - Pre-Alpha',
    ],
    long_description = """Note: this module is not yet ready for 
use in production. Developed for askbot forum - please ask questions
at `http://askbot.org <http://askbot.org>`_.
"""
)
