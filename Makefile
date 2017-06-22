default:
.PHONY :  install install_bundle get_amalgamation upload test clean

install: clean
	python setup.py install

install_bundle: clean
	python setup.py install --bundled

get_amalgamation:
	scripts/get_latest_amalgamation.sh amalgamation_latest

upload:
	python setup.py sdist upload -r pypi 

test:
	rm -f tests/*.db
	cd tests && ./run.sh
	rm -f tests/*.db

clean:
	rm -rf build dist
