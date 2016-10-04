DIST=dist/bitmask
NEXT_VERSION = $(shell cat pkg/next-version)
DIST_VERSION = dist/bitmask-$(NEXT_VERSION)/
include pkg/pyinst/build.mk

clean:
	find . -type f -name "*.py[co]" -delete
	find . -type d -name "__pycache__" -delete

dev-mail:
	pip install -e '.[mail]'
	make -C ui dev-install-prebuilt

dev-all:
	pip install -e '.[all]'

uninstall:
	pip uninstall leap.bitmask

doc:
	cd docs && make html
