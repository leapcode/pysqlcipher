# -*- mode: python -*-

block_cipher = None


a = Analysis(['../../src/leap/bitmask/gui/app.py'],
             pathex=[
		'/usr/lib/python2.7/dist-packages/'],
             binaries=None,
             datas=None,
             hiddenimports=[
               'zope.interface', 'zope.proxy',
               'PyQt5.QtCore', 'PyQt5.QtGui', 'PyQt5.QtWebKit',
               'pysqlcipher', 'service_identity',
               'leap.common', 'leap.bitmask'
               ],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='bitmask',
          debug=False,
          strip=False,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='bitmask')
