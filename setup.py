#!/usr/bin/env python

import sys
from setuptools import setup, find_packages
import errno
import os


if sys.argv[1] == 'install':

    #Build Rest config options from defaults
    with open('sphinx/config.rst', 'w') as rst:
        with open('certain/certain.cfg.defaults') as cfg:
            for line in cfg.readlines():
                if line.startswith('['):
                    rst.write(line + "------------------------------\n\n")
                elif line.startswith('#'):
                    comment = line[1:]
                    rst.write("\n\t\t" + comment)
                else:
                    rst.write("\t" + line)

    #Build sphinx documentation
    os.system('sphinx-build -b html sphinx ' + os.path.join('sphinx', 'build'))

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
                if line.isspace():
                    c.write(line)
                else:
                    c.write("#" + line)

    data_files = []

    #Generate a list of sphinx doc paths to install
    sphinxfiles = []
    for (dirpath, dirs, files) in os.walk(os.path.join('sphinx', 'build')):
        try:
            del dirs[dirs.index('.doctrees')]
        except ValueError:
            pass
        #strip off the initial 'sphinx/build/' for tgt path creation
        subdir = dirpath[13:]
        sphinxfiles.append(
            (os.path.join('share', 'doc', 'certain', 'html', subdir),
             [os.path.join(dirpath, name) for name in files]))

    #Add data files to array
    data_files.extend(sphinxfiles)
    data_files.append(
        (os.path.join('/etc', 'init.d'), ['etc/init.d/certain']))
    data_files.append(
        (os.path.join('/etc', 'certain'), ['etc/certain/certain.cfg']))

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
    data_files = data_files
    )
