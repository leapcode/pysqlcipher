from os import makedirs
from os.path import abspath, join, isfile, isdir

from twisted.python import logfile

from leap.common.config import get_path_prefix


def getLogPath():
    configdir = abspath(join(get_path_prefix(), 'leap'))
    if not isdir(configdir):
        makedirs(configdir)
    log_path = join(configdir, 'bitmaskd.log')
    return log_path


def logFileFactory():
    log_path = getLogPath()
    rotate = isfile(log_path)
    _logfile = logfile.LogFile.fromFullPath(log_path, maxRotatedFiles=5)
    if rotate:
        _logfile.rotate()
    return _logfile
