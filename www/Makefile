build:
	npm install
	npm run build:production

build-dev:
	npm run watch 

clean:
	rm -rf public
	rm -rf node_modules

py-pkg:
	touch leap/bitmask_www/__init__.py
	cp -r public/ leap/bitmask_www

pydist: pydist-clean build py-pkg
	python setup.py bdist_wheel

pydist-dev: pydist-clean build py-pkg
	pip install -e .

pydist-install: pydist
	pip install dist/*.whl

pydist-clean:
	rm -rf build dist
	rm -rf leap/bitmask_www/*

uninstall:
	pip uninstall leap.bitmask_www

all: clean build pydist

.PHONY: clean build install all
