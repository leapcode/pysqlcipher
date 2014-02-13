#-*- coding: ISO-8859-1 -*-
# setup.py: the distutils script
#
# Copyright (C) 2013 Kali Kaneko <kali@futeisha.org> (sqlcipher support)
# Copyright (C) 2005-2010 Gerhard Häring <gh@ghaering.de>
#
# This file is part of pysqlcipher.
#
# This software is provided 'as-is', without any express or implied
# warranty.  In no event will the authors be held liable for any damages
# arising from the use of this software.
#
# Permission is granted to anyone to use this software for any purpose,
# including commercial applications, and to alter it and redistribute it
# freely, subject to the following restrictions:
#
# 1. The origin of this software must not be misrepresented; you must not
#    claim that you wrote the original software. If you use this software
#    in a product, an acknowledgment in the product documentation would be
#    appreciated but is not required.
# 2. Altered source versions must be plainly marked as such, and must not be
#    misrepresented as being the original software.
# 3. This notice may not be removed or altered from any source distribution.
import os
import re
import sys
import urllib
import zipfile

from types import ListType, TupleType

#from distutils.core import setup, Extension, Command
from setuptools import setup, Extension, Command
from distutils.command.build import build
#from distutils.command.build_ext import build_ext
from distutils.dep_util import newer_group
from distutils.errors import DistutilsSetupError
from distutils import log

import cross_bdist_wininst

#YOU'LL NEED THIS: https://python-for-android.googlecode.com/files/python-lib_r16.zip AND THIS DESCRIPTION WILL HELP, TOO: 
# https://code.google.com/p/python-for-android/wiki/BuildingModules

from py4a import patch_distutils 
patch_distutils()

# If you need to change anything, it should be enough to change setup.cfg.

sqlite = "sqlite"

PYSQLITE_EXPERIMENTAL = False

DEV_VERSION = None
#DEV_VERSION = "02"

sources = ["src/module.c", "src/connection.c", "src/cursor.c", "src/cache.c",
           "src/microprotocols.c", "src/prepare_protocol.c", "src/statement.c",
           "src/util.c", "src/row.c"]
depends = []

           
if PYSQLITE_EXPERIMENTAL:
    sources.append("src/backup.c")

include_dirs = ["amalgamation"] 
library_dirs = []
libraries = []
runtime_library_dirs = []
extra_objects = []
define_macros = []

long_description = \
"""Python interface to SQLCipher

pysqlcipher is an interface to the SQLite 3.x embedded relational
database engine. It is almost fully compliant with the Python database API
version 2.0. At the same time, it also exposes the unique features of
SQLCipher."""

if sys.platform != "win32":
    define_macros.append(('MODULE_NAME', '"pysqlcipher.dbapi2"'))
else:
    define_macros.append(('MODULE_NAME', '\\"pysqlcipher.dbapi2\\"'))


class DocBuilder(Command):
    description = "Builds the documentation"
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        import shutil
        try:
            shutil.rmtree("build/doc")
        except OSError:
            pass
        os.makedirs("build/doc")
        rc = os.system("sphinx-build doc/sphinx build/doc")
        if rc != 0:
            print ("Is sphinx installed? If not, "
                   "try 'sudo easy_install sphinx'.")

AMALGAMATION_ROOT = "amalgamation"


def get_amalgamation():
    """Download the SQLite amalgamation if it isn't there, already."""
    if os.path.exists(AMALGAMATION_ROOT):
        return
    os.mkdir(AMALGAMATION_ROOT)
    print "Downloading amalgation."

    # XXX upload the amalgamation file to downloads.leap.se
    amalgamation_url = ("http://futeisha.org/sqlcipher/"
                        "amalgamation-sqlcipher-2.1.0.zip")

    # and download it
    print 'amalgamation url: %s' % (amalgamation_url,)
    urllib.urlretrieve(amalgamation_url, "tmp.zip")

    zf = zipfile.ZipFile("tmp.zip")
    files = ["sqlite3.c", "sqlite3.h"]
    directory = zf.namelist()[0]

    for fn in files:
        print "Extracting", fn
        outf = open(AMALGAMATION_ROOT + os.sep + fn, "wb")
        outf.write(zf.read(directory + fn))
        outf.close()
    zf.close()
    os.unlink("tmp.zip")



def get_setup_args():

    PYSQLITE_VERSION = None

    version_re = re.compile('#define PYSQLITE_VERSION "(.*)"')
    f = open(os.path.join("src", "module.h"))
    for line in f:
        match = version_re.match(line)
        if match:
            PYSQLITE_VERSION = match.groups()[0]
            PYSQLITE_MINOR_VERSION = ".".join(PYSQLITE_VERSION.split('.')[:2])
            break
    f.close()

    if DEV_VERSION:
        PYSQLITE_VERSION += ".dev%s" % DEV_VERSION

    if not PYSQLITE_VERSION:
        print "Fatal error: PYSQLITE_VERSION could not be detected!"
        sys.exit(1)

    library_dirs=["lib"]
    libraries=["sqlcipher"]   
    
    setup_args = dict(
        name="pysqlcipher",
        version=PYSQLITE_VERSION,
        #version="0.0.1",
        description="DB-API 2.0 interface for SQLCIPHER 3.x",
        long_description=long_description,
        author="Kali Kaneko",
        author_email="kali@futeisha.org",
        license="zlib/libpng",  # is THIS a license?
        # It says MIT in the google project
        platforms="ALL",
        url="http://github.com/leapcode/pysqlcipher/",
        # Description of the modules and packages in the distribution
        package_dir={"pysqlcipher": "lib"},
        package_data={'pysqlcipher': ['*.so']},
        packages=["pysqlcipher", "pysqlcipher.test"] +
            (["pysqlcipher.test.py25"], [])[sys.version_info < (2, 5)],
        scripts=[],
        ext_modules=[
            Extension(
                name="pysqlcipher._sqlite",
                sources=sources,
                depends=depends,
                include_dirs=include_dirs,
                library_dirs=library_dirs,
                runtime_library_dirs=runtime_library_dirs,
                libraries=libraries,
                extra_objects=extra_objects,
                define_macros=define_macros)
        ],
        classifiers=[
            "Development Status :: 4 - Beta",
            "Intended Audience :: Developers",
            "License :: OSI Approved :: zlib/libpng License",
            "Operating System :: MacOS :: MacOS X",
            "Operating System :: Microsoft :: Windows",
            "Operating System :: POSIX",
            "Programming Language :: C",
            "Programming Language :: Python",
            "Topic :: Database :: Database Engines/Servers",
            "Topic :: Software Development :: Libraries :: Python Modules"],
        cmdclass={"build_docs": DocBuilder}
    )

    setup_args["cmdclass"].update(
        {"build_docs": DocBuilder
        })
    return setup_args


def main():
    get_amalgamation()
    setup(**get_setup_args())

if __name__ == "__main__":
    main()
