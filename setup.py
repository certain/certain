#!/usr/bin/env python

from setuptools import setup, find_packages

#Copy certain.cfg.defaults to certain.cfg
with open('etc/certain.cfg', 'w') as c:
    c.write("Certain's default configuration given below.\n" \
            "Uncomment lines as appropriate to change.\n\n")
    with open('certain/certain.cfg.defaults') as f:
        for line in f:
            c.write("## " + line)

setup(
    name = 'certain',
    version = '0.1.0',
    description = 'X509 Certificate Management & Distribution Service',
    author = 'Matthew Richardson',
    author_email = 'm.richardson@ed.ac.uk',
    url = 'http://www.example.com/certain',
    packages = find_packages(),
    include_package_data = True,
    package_data = {'': ['certain.cfg.defaults']},
    install_requires = ['dulwich', 'M2Crypto', 'git'],
    scripts = ['bin/certain', 'bin/storeserver'],
    data_files = [
        ('/etc/init.d', ['etc/init.d/certain']),
        ('/etc/certain', ['etc/certain.cfg'])
        ]
    )

