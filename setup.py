#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name = 'certain',
    version = '0.1.0',
    description = 'X509 Certificate Management & Distribution Service',
    author = 'Matthew Richardson',
    author_email = 'm.richardson@ed.ac.uk',
    url = 'http://www.example.com/certain',
    packages = ['certain',
                'certain.StoreHandler',
                'certain.StoreServer',
                'certain.ExpiryHandler'],
    install_requires = ['dulwich', 'M2Crypto', 'git'],
    scripts = ['bin/certain', 'bin/storeserver'],
    data_files = [
        ('/etc/init.d', ['etc/init.d/certain']),
        ('/etc/certain', ['etc/certain.cfg.example'])
        ]
    )

