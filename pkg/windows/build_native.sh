#!/bin/sh
rm -rf dist build
pip uninstall leap.bitmask
python setup.py bdist_wheel
pip install dist/*.whl
pyinstaller.exe -y pkg/pyinst/app.spec
pkg/pyinst/win_postbuild.bat
