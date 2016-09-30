install: clean
	python setup.py install

install_bundle: clean
	python setup.py install --bundled

get_amalgamation:
	scripts/get_latest_amalgamation.sh amalgamation_latest

upload:
	python setup.py sdist upload -r pypi 

clean:
	rm -rf build dist
