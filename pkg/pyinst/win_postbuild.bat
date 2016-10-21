SET DIST=%CD%\dist\bitmask
cp %VIRTUAL_ENV%/Lib/site-packages/_scrypt.pyd %DIST%
cp %VIRTUAL_ENV%/Lib/site-packages/zmq/libzmq.pyd %DIST%
cp %VIRTUAL_ENV%/Lib/site-packages/leap/common/cacert.pem %DIST%
cp %CD%\src\leap\bitmask\core\bitmaskd.tac %DIST%
mkdir %DIST%\leap
mkdir %DIST%\leap\soledad\common\l2db\backends
mkdir %DIST%\apps\mail
cp %CD%/../gpg/* %DIST%\apps\mail\
cp %VIRTUAL_ENV%/Lib/site-packages/leap/soledad/common/l2db/backends/dbschema.sql %DIST%\leap\soledad\common\l2db\backends
cp -r %VIRTUAL_ENV%/Lib/site-packages/leap/bitmask_js %DIST%\leap\
