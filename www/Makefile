build:
	npm install
	npm run build:production

build-dev:
	npm run watch 

clean:
	rm -rf public
	rm -rf node_modules

pydist: pydist-clean build
	touch leap/bitmask_www/__init__.py
	cp -r public/ leap/bitmask_www
	python setup.py bdist_wheel

pydist-dev:
	pip install -e .

pydist-clean:
	rm -rf build dist
	rm -rf leap/bitmask_www/*

uninstall:
	pip uninstall leap.bitmask_www

all: clean build pydist

.PHONY: clean build install all
