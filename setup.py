import ez_setup
ez_setup.use_setuptools()
from setuptools import setup, find_packages
import sys

#NOTE: if you want to develop authenticator
#you might want to install django-debug-toolbar as well

install_requires = [
    'django==1.1.2',
    'Jinja2',
    'Coffin==0.3.0',
    'South>=0.7.1',
    'oauth2',
    'recaptcha-client',
    'markdown2',
    'html5lib',
    'django-keyedcache',
    'django-threaded-multihost',
    'unidecode',
]

import authenticator

setup(
    name = "authenticator",
    version = authenticator.get_version(),
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
