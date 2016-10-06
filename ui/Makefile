#
# builds for development mode
#

dev-build: build-clean make-init
	npm install
	npm run build

dev-install: dev-build
	pip install -e pydist

# installs python package, but does not rebuild the js.
# for usage when you don't want to install nodejs
dev-install-prebuilt:
	pip install -e pydist

#
# distribution builds
#

dist-build: build-clean make-init
	npm install
	npm run build:production
	cd pydist && python setup.py bdist_wheel

dist-install: dist-build
	pip install pydist/dist/*.whl

#
# clean up and set up
#

make-init:
	test -d pydist/leap/bitmask_js || mkdir -p pydist/leap/bitmask_js
	touch pydist/leap/bitmask_js/__init__.py

build-clean:
	rm -rf pydist/leap/bitmask_js
	rm -rf pydist/dist
	rm -rf pydist/build

clean: build-clean
	rm -rf node_modules

uninstall:
	pip uninstall leap.bitmask_js
