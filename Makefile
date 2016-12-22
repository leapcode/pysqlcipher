DIST=dist/bitmask
NEXT_VERSION = $(shell cat pkg/next-version)
DIST_VERSION = dist/bitmask-$(NEXT_VERSION)/
include pkg/pyinst/build.mk

clean:
	find . -type f -name "*.py[co]" -delete
	find . -type d -name "__pycache__" -delete

dev-mail:
	pip install -e '.[mail]'

dev-backend:
	pip install -e '.[backend]'

dev-all:
	pip install -e '.[all]'

uninstall:
	pip uninstall leap.bitmask

test_e2e:
	tests/e2e/e2e-test.sh

qt-resources:
	pyrcc5 pkg/branding/icons.qrc -o src/leap/bitmask/gui/app_rc.py

doc:
	cd docs && make html
