#!/usr/bin/python

#git describe versioning magic from http://gist.github.com/300803

import sys
from setuptools import setup, find_packages, Command
import errno
import os
from PyQt4 import uic
from subprocess import Popen, PIPE


if len(sys.argv) > 1 and (
        not sys.argv[1].startswith('-') and sys.argv[1] != 'clean'):
    try:
        with open('certain/CertainForm.py'):
            pass
    except IOError as e:
        if e.errno != errno.ENOENT:
            raise
        sys.argv.insert(1, 'prebuild')
        sys.argv.insert(2, 'build_sphinx')


class PreBuildCommand(Command):
    """Custom commands to be run at start of setup.py"""

    description = "Custom commands to be run before main command"

    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        self.compile_ui()
        self.generate_config()
        self.generate_docs()
        try:
            os.makedirs('setup/sphinx')
        except OSError, e:
            if e.errno != errno.EEXIST:
                raise

    def compile_ui(self):
        with open('certain/CertainForm.py', 'w') as f:
            uic.compileUi('certain/certain.ui', f)

    def generate_config(self):
        try:
            os.makedirs('setup/etc/certain')
        except OSError, e:
            if e.errno != errno.EEXIST:
                raise
        #Copy certain.conf.defaults to certain.conf
        with open('setup/etc/certain/certain.conf', 'w') as c:
            c.write("# Certain's default configuration is given below.\n"
                    "# Uncomment lines as appropriate to change.\n\n")
            with open('certain/certain.conf.defaults') as f:
                for line in f:
                    if line.isspace() or line.startswith('['):
                        c.write(line)
                    else:
                        c.write("#" + line)

    def generate_docs(self):
        #Build reSt config options from defaults
        comment = []
        with open('sphinx/config.rst', 'w') as rst:
            with open('certain/certain.conf.defaults') as cfg:
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


def call_git_describe(abbrev=4):
    try:
        p = Popen(['git', 'describe', '--abbrev=%d' % abbrev], stdout=PIPE)
        return p.communicate()[0].split('\n')[0].strip()
    except Exception:
        return None


def read_release_version():
    try:
        with open("RELEASE-VERSION") as f:
            return f.readlines()[0].strip()
    except Exception:
        return None


def write_release_version(version):
    with open("RELEASE-VERSION", "w") as f:
        f.write("%s\n" % version)


def get_git_version(abbrev=4):
    # First try to get the current version using `git describe`.

    version = call_git_describe(abbrev)

    # If that doesn't work, fall back on the value that's in
    # RELEASE-VERSION.

    release_version = read_release_version()
    if version is None:
        version = release_version

    # If we still don't have anything, that's an error.

    if version is None:
        raise ValueError("Cannot find the version number!")

    # If the current version is different from what's in the
    # RELEASE-VERSION file, update the file to be current.

    if version != release_version:
        write_release_version(version)

    # Finally, return the current version.

    return version


if len(sys.argv) > 1 and sys.argv[1] == 'clean':
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
        (os.path.join('share', 'doc', 'certain', subdir),
         [os.path.join(dirpath, name) for name in files]))

#Add data files to array
data_files.extend(sphinxfiles)
data_files.append(
    (os.path.join('/etc', 'init'),
    ['etc/init/certain.conf', 'etc/init/storeserver.conf']))
data_files.append(
    (os.path.join('/etc', 'certain'), ['setup/etc/certain/certain.conf']))

cmdclass = {}
cmdclass['prebuild'] = PreBuildCommand

setup(
    name = 'certain',
    version = get_git_version(),
    description = 'X509 Certificate Management & Distribution Service',
    author = 'Matthew Richardson',
    author_email = 'm.richardson@ed.ac.uk',
    url = 'https://github.com/certain/certain',
    packages = find_packages(),
    include_package_data = True,
    package_data = {'': ['certain.conf.defaults', 'RELEASE-VERSION']},
    install_requires = ['dulwich', 'M2Crypto'],
    scripts = ['bin/certain', 'bin/storeserver', 'bin/certaingui'],
    data_files = data_files,
    cmdclass = cmdclass,
    )
