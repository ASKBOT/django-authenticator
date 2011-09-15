import ez_setup
ez_setup.use_setuptools()
from setuptools import setup, find_packages
import sys

#NOTE: if you want to develop authenticator
#you might want to install django-debug-toolbar as well

install_requires = [
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
    version = django_authenticator.get_version(),
    description = 'authentication client and server',
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
    install_requires = install_requires,
    classifiers = [
    ],
    long_description = ''
)
