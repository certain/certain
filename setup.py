#!/usr/bin/python

#git describe versioning magic from http://gist.github.com/300803

import sys
from setuptools import setup, find_packages
from distutils.core import setup, Command
import errno
import os
from PyQt4 import uic
from subprocess import Popen, PIPE
import certain
from collections import defaultdict

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


class AutoDoc(object):

    def __init__(self, module):
        self.module = module

        self.dispatch = defaultdict(lambda: self.Undef,
                     { 'class': self.parse_class,
                      'type': self.parse_class,
                      'classobj': self.parse_class,
                      'abc.ABCMeta': self.parse_class,
                      'function': self.parse_function,
                      'module': self.parse_module,
                      })


    def Undef(self, name, parentmodule=None):
        pass
        # print >>sys.stderr, "WARNING: Unhandled object: %s %s" % (parentmodule,name)

    def parse_class(self, name, parentmodule=None):
        if parentmodule:
                func = getattr(parentmodule, name.split(".")[-1])
        else:
                func = getattr(self.module, name)
        try:
            if self.module.__name__ not in func.__file__:
                return
        except AttributeError:
            #Some modules have no __file__ attribute - all Certain ones should
            if not hasattr(func, '__module__') or self.module.__name__ not in func.__module__:
                return
        print >>self.f_py, "\n.. autoclass:: %s\n   :members:" % func.__name__

    def parse_function(self, name, parentmodule=None):
        if parentmodule:
                func = getattr(parentmodule, name.split(".")[-1])
        else:
                func = getattr(self.module, name)
        try:
            if self.module.__name__ not in func.__file__:
                return
        except AttributeError:
            #Some modules have no __file__ attribute - all Certain ones should
            if not hasattr(func, '__module__') or self.module.__name__ not in func.__module__:
                return
        # We do not need to list functions explicitly, as they included via automodule.
        #print >>self.f_py, ".. autofunction:: %s" % func.__name__

    def parse_module(self, name='', parentmodule=None):
        if parentmodule:
            if name:
                func = getattr(parentmodule, name.split(".")[-1])
            else:
                func = parentmodule
                name = parentmodule.__name__
        else:
            if name:
                func = getattr(self.module, name)
            else:
                func = self.module
                name = self.module.__name__
        try:
            if self.module.__name__ not in func.__file__:
                return
        except AttributeError:
            #Some modules have no __file__ attribute - all Certain ones should
            if not hasattr(func, '__module__') or self.module.__name__ not in func.__module__:
                return
        print >>self.f_py, "\n%s\n%s\n\n.. automodule:: %s\n   :members:" % (
                name, '-' * len(name), name)

        objects = []
        for attr in dir(func):
            obj = getattr(func, attr)
            objtype = str(
                type(obj)
                ).split("'")[1]
            objects += ((objtype, self.dispatch[objtype], name + '.' + attr), )
        for obj in sorted(objects, key=self.sortclasses):
            obj[1](obj[2], func) # Call the appropriate parser

    @staticmethod
    def sortclasses(a):
        return a[0] not in ('class', 'type', 'classobj'),  a[1]

    def generate(self, f_py):
        self.f_py = f_py
        print >>f_py, ":mod:`%s` --- Python Module" % self.module.__name__
        print >>f_py
        print >>f_py, "Modules"
        print >>f_py, "======="
        self.parse_module()


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

        autodoc = AutoDoc(certain)
        with open('sphinx/certain-py.rst', 'w') as f_py:
            autodoc.generate(f_py)

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
    for file in ['certain/CertainForm.py',
                 'sphinx/config.rst',
                 'sphinx/certain-py.rst']:
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
