#!/usr/bin/python

import sys
from setuptools import setup, find_packages
import errno
import os
from PyQt4 import uic


if sys.argv[1] == 'install':
    #Build reSt config options from defaults
    comment = []
    with open('sphinx/config.rst', 'w') as rst:
        with open('certain/certain.cfg.defaults') as cfg:
            for line in cfg:
                if line.startswith('['):
                    rst.write(line + "------------------------------\n\n")
                elif line.startswith('# note: '):
                    rst.write('\t.. note:: ' + line[8:])
                elif line.startswith('#'):
                    comment += ['\n\t\t' + line[1:]]
                else:
                    rst.write("\t" + line + ''.join(comment))
                    comment = []

    #Build sphinx documentation
    os.system('sphinx-build -b html sphinx ' + os.path.join('setup', 'sphinx'))

    try:
        os.makedirs('setup/etc/certain')
    except OSError, e:
        if e.errno != errno.EEXIST:
            raise

    #Copy certain.cfg.defaults to certain.cfg
    with open('setup/etc/certain/certain.cfg', 'w') as c:
        c.write("# Certain's default configuration is given below.\n"
                "# Uncomment lines as appropriate to change.\n\n")
        with open('certain/certain.cfg.defaults') as f:
            for line in f:
                if line.isspace() or line.startswith('['):
                    c.write(line)
                else:
                    c.write("#" + line)

elif sys.argv[1] == 'build':
    with open('certain/CertainForm.py', 'w') as f:
        uic.compileUi('certain/certain.ui', f)

elif sys.argv[1] == 'clean':
    for dir in ['setup', 'certain.egg-info']:
        try:
            for dirpath, dirs, files in os.walk(dir, topdown=False):
                map(os.unlink, [os.path.join(dirpath, name) for name in files])
                map(os.rmdir, [os.path.join(dirpath, name) for name in dirs])
            os.rmdir(dir)
        except OSError:
            pass
    for file in ['certain/CertainForm.py', 'sphinx/config.rst']:
        try:
            os.unlink(file)
        except OSError:
            pass

data_files = []

#Generate a list of sphinx doc paths to install
sphinxfiles = []
for (dirpath, dirs, files) in os.walk(os.path.join('setup', 'sphinx')):
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
    (os.path.join('/etc', 'init.d'),
    ['etc/init.d/certain', 'etc/init.d/storeserver']))
data_files.append(
    (os.path.join('/etc', 'certain'), ['setup/etc/certain/certain.cfg']))

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
    scripts = ['bin/certain', 'bin/storeserver', 'bin/certaingui'],
    data_files = data_files
    )
