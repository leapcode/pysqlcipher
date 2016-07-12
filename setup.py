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

from distutils.command.build import build
from distutils.command.build_ext import build_ext
from distutils.dep_util import newer_group
from distutils.errors import DistutilsSetupError
from distutils import log

import setuptools
from setuptools import Extension, Command

import cross_bdist_wininst

# If you need to change anything, it should be enough to change setup.cfg.

sqlite = "sqlite"

PYSQLITE_EXPERIMENTAL = False

DEV_VERSION = None

PATCH_VERSION = None

sources = ["src/module.c", "src/connection.c", "src/cursor.c", "src/cache.c",
           "src/microprotocols.c", "src/prepare_protocol.c", "src/statement.c",
           "src/util.c", "src/row.c"]

if PYSQLITE_EXPERIMENTAL:
    sources.append("src/backup.c")


if sys.platform == "darwin":
    # Work around clang raising hard error for unused arguments
    os.environ['CFLAGS'] = "-Qunused-arguments"
    print "CFLAGS", os.environ['CFLAGS']

include_dirs = []
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

    amalgamation_url = ("https://downloads.leap.se/libs/pysqlcipher/"
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


class AmalgamationBuilder(build):
    description = ("Build a statically built pysqlcipher "
                   "downloading and using a sqlcipher amalgamation.")

    def __init__(self, *args, **kwargs):
        MyBuildExt.amalgamation = True
        MyBuildExt.static = True
        build.__init__(self, *args, **kwargs)


class LibSQLCipherBuilder(build_ext):

    description = ("Build C extension linking against libsqlcipher library.")

    def build_extension(self, ext):
        ext.extra_compile_args.append("-I/usr/include/sqlcipher/")
        ext.extra_link_args.append("-lsqlcipher")
        build_ext.build_extension(self, ext)


class MyBuildExt(build_ext):
    amalgamation = True  # We want amalgamation on the default build for now
    static = False

    def build_extension(self, ext):
        if self.amalgamation:
            get_amalgamation()
            # build with fulltext search enabled
            ext.define_macros.append(
                ("SQLITE_ENABLE_FTS3", "1"))
            ext.define_macros.append(
                ("SQLITE_ENABLE_RTREE", "1"))

            # SQLCipher options
            ext.define_macros.append(
                ("SQLITE_ENABLE_LOAD_EXTENSION", "1"))
            ext.define_macros.append(
                ("SQLITE_HAS_CODEC", "1"))
            ext.define_macros.append(
                ("SQLITE_TEMP_STORE", "2"))
            ext.define_macros.append(
                ("HAVE_USLEEP", "1"))

            ext.sources.append(os.path.join(AMALGAMATION_ROOT, "sqlite3.c"))
            ext.include_dirs.append(AMALGAMATION_ROOT)

            if sys.platform == "win32":
                # Try to locate openssl
                openssl_conf = os.environ.get('OPENSSL_CONF')
                if not openssl_conf:
                    sys.exit('Fatal error: OpenSSL could not be detected!')
                openssl = os.path.dirname(os.path.dirname(openssl_conf))

                # Configure the compiler
                ext.include_dirs.append(os.path.join(openssl, "include"))
                ext.define_macros.append(("inline", "__inline"))

                # Configure the linker
                ext.extra_link_args.append("libeay32.lib")
                ext.extra_link_args.append(
                    "/LIBPATH:" + os.path.join(openssl, "lib")
                )
            else:
                ext.extra_link_args.append("-lcrypto")

        if self.static:
            self._build_extension(ext)
        else:
            build_ext.build_extension(self, ext)

    def _build_extension(self, ext):
        sources = ext.sources
        if sources is None or type(sources) not in (ListType, TupleType):
            raise DistutilsSetupError, \
                ("in 'ext_modules' option (extension '%s'), " +
                 "'sources' must be present and must be " +
                 "a list of source filenames") % ext.name
        sources = list(sources)

        ext_path = self.get_ext_fullpath(ext.name)
        depends = sources + ext.depends
        if not (self.force or newer_group(depends, ext_path, 'newer')):
            log.debug("skipping '%s' extension (up-to-date)", ext.name)
            return
        else:
            log.info("building '%s' extension", ext.name)

        # First, scan the sources for SWIG definition files (.i), run
        # SWIG on 'em to create .c files, and modify the sources list
        # accordingly.
        sources = self.swig_sources(sources, ext)

        # Next, compile the source code to object files.

        # XXX not honouring 'define_macros' or 'undef_macros' -- the
        # CCompiler API needs to change to accommodate this, and I
        # want to do one thing at a time!

        # Two possible sources for extra compiler arguments:
        #   - 'extra_compile_args' in Extension object
        #   - CFLAGS environment variable (not particularly
        #     elegant, but people seem to expect it and I
        #     guess it's useful)
        # The environment variable should take precedence, and
        # any sensible compiler will give precedence to later
        # command line args.  Hence we combine them in order:
        extra_args = ext.extra_compile_args or []

        macros = ext.define_macros[:]
        for undef in ext.undef_macros:
            macros.append((undef,))

        objects = self.compiler.compile(sources,
                                        output_dir=self.build_temp,
                                        macros=macros,
                                        include_dirs=ext.include_dirs,
                                        debug=self.debug,
                                        extra_postargs=extra_args,
                                        depends=ext.depends)

        # XXX -- this is a Vile HACK!
        #
        # The setup.py script for Python on Unix needs to be able to
        # get this list so it can perform all the clean up needed to
        # avoid keeping object files around when cleaning out a failed
        # build of an extension module.  Since Distutils does not
        # track dependencies, we have to get rid of intermediates to
        # ensure all the intermediates will be properly re-built.
        #
        self._built_objects = objects[:]

        # Now link the object files together into a "shared object" --
        # of course, first we have to figure out all the other things
        # that go into the mix.
        if ext.extra_objects:
            objects.extend(ext.extra_objects)
        extra_args = ext.extra_link_args or []

        # Detect target language, if not provided
        language = ext.language or self.compiler.detect_language(sources)

        #self.compiler.link_shared_object(
            #objects, ext_path,
            #libraries=self.get_libraries(ext),
            #library_dirs=ext.library_dirs,
            #runtime_library_dirs=ext.runtime_library_dirs,
            #extra_postargs=extra_args,
            #export_symbols=self.get_export_symbols(ext),
            #debug=self.debug,
            #build_temp=self.build_temp,
            #target_lang=language)

        # XXX may I have a static lib please?
        # hmm but then I cannot load that extension, or can I?
        output_dir = os.path.sep.join(ext_path.split(os.path.sep)[:-1])

        self.compiler.create_static_lib(
            objects,
            #XXX get library name ... splitting ext_path?
            "sqlite",
            output_dir=output_dir,
            target_lang=language)

    def __setattr__(self, k, v):
        # Make sure we don't link against the SQLite
        # library, no matter what setup.cfg says
        if self.amalgamation and k == "libraries":
            v = None
        self.__dict__[k] = v


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

    if not PYSQLITE_VERSION:
        print "Fatal error: PYSQLITE_VERSION could not be detected!"
        sys.exit(1)

    if DEV_VERSION:
        PYSQLITE_VERSION += ".dev%s" % DEV_VERSION

    if PATCH_VERSION:
        PYSQLITE_VERSION += "-%s" % PATCH_VERSION

    # Need to bump minor version, patch handled badly.
    PYSQLCIPHER_VERSION = "2.6.5"

    setup_args = dict(
        name="pysqlcipher",
        #version=PYSQLITE_VERSION,
        version=PYSQLCIPHER_VERSION,
        description="DB-API 2.0 interface for SQLCIPHER 3.x",
        long_description=long_description,
        author="Kali Kaneko",
        author_email="kali@leap.se",
        license="zlib/libpng",
        # XXX check
        # It says MIT in the google project
        platforms="ALL",
        url="http://github.com/leapcode/pysqlcipher/",
        # Description of the modules and packages in the distribution
        package_dir={"pysqlcipher": "lib"},
        packages=["pysqlcipher", "pysqlcipher.test"] +
            (["pysqlcipher.test.py25"], [])[sys.version_info < (2, 5)],
        scripts=[],
        ext_modules=[
            Extension(
                name="pysqlcipher._sqlite",
                sources=sources,
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
        {"build_docs": DocBuilder,
         "build_ext": MyBuildExt,
         "build_static": AmalgamationBuilder,
         "build_sqlcipher": LibSQLCipherBuilder,
         "cross_bdist_wininst": cross_bdist_wininst.bdist_wininst})
    return setup_args


def main():
    setuptools.setup(**get_setup_args())

if __name__ == "__main__":
    main()
