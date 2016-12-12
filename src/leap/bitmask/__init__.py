import sys
import pkg_resources
from ._version import get_versions

if not getattr(sys, 'frozen', False):
    # FIXME: HACK for https://github.com/pypa/pip/issues/3
    # Without this 'fix', there are resolution conflicts when pip installs at
    # the same time bitmask in develop mode and other package in the leap
    # namespace from pypi. For instance:
    # 'pip install -e .' and 'pip install leap.common'
    pkg_resources.get_distribution('leap.bitmask')

__version__ = get_versions()['version']
del get_versions
