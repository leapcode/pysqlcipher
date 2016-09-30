install: clean
	python setup.py install

install_bundle: clean
	python setup.py install --bundled

clean:
	rm -rf build dist
