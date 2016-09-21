#
# builds for development mode
#

dev-build: build-clean
	npm install
	npm run build
	touch pydist/leap/bitmask_js/__init__.py

dev-install: dev-build
	pip install -e pydist

#
# installs python package, but does not rebuild the js.
# for usage when you don't want to install nodejs
#
dev-install-prebuilt:
	pip install -e pydist


#
# distribution builds
#

dist-build: build-clean
	npm install
	npm run build:production
	touch pydist/leap/bitmask_js/__init__.py
	cd pydist && python setup.py bdist_wheel

dist-install: dist-build
	pip install pydist/dist/*.whl

#
# cleaning up
#

build-clean:
	rm -rf pydist/leap/bitmask_js
	rm -rf pydist/dist
	rm -rf pydist/build

clean: build-clean
	rm -rf node_modules

uninstall:
	pip uninstall leap.bitmask_js
