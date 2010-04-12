#!/usr/bin/env python

import sys
from setuptools import setup, find_packages
import errno
import os


if sys.argv[1] == 'install':
    os.system('./make_doc.sh')

    try:
        os.mkdir('etc/certain')
    except OSError, e:
        if e.errno != errno.EEXIST:
            raise

    #Copy certain.cfg.defaults to certain.cfg
    with open('etc/certain/certain.cfg', 'w') as c:
        c.write("# Certain's default configuration is given below.\n"
                "# Uncomment lines as appropriate to change.\n\n")
        with open('certain/certain.cfg.defaults') as f:
            for line in f:
                c.write("#" + line)

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
        (os.path.join('/etc', 'init.d'), ['etc/init.d/certain']),
        (os.path.join('/etc', 'certain'), ['etc/certain/certain.cfg']),
        (os.path.join('share', 'man', 'man8'), ['man/certain.8']),
        (os.path.join('share', 'man', 'man5'), ['man/certain.cfg.5']),
        (os.path.join('share', 'doc', 'certain', 'html'),
             [os.path.join('apidoc', name) for name in os.listdir('apidoc')]),
        ]
    )
