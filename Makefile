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

dev-latest-backend: dev-backend
	pip install -e 'git+https://0xacab.org/leap/leap_pycommon@master#egg=leap.common'
	pip install -e 'git+https://0xacab.org/leap/soledad@develop#egg=leap.soledad.common&subdirectory=common'
	pip install -e 'git+https://0xacab.org/leap/soledad@develop#egg=leap.soledad.client&subdirectory=client'

dev-all:
	pip install -e '.[all]'

dev-latest-all: dev-all
	pip install -e 'git+https://0xacab.org/leap/leap_pycommon@master#egg=leap.common'
	pip install -e 'git+https://0xacab.org/leap/soledad@develop#egg=leap.soledad.common&subdirectory=common'
	pip install -e 'git+https://0xacab.org/leap/soledad@develop#egg=leap.soledad.client&subdirectory=client'

uninstall:
	pip uninstall leap.bitmask

test_e2e:
	tests/e2e/e2e-test.sh

qt-resources:
	pyrcc5 pkg/branding/icons.qrc -o src/leap/bitmask/gui/app_rc.py

doc:
	cd docs && make html
