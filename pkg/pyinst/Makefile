build: clean
	pyinstaller -y app.spec
	cp $(VIRTUAL_ENV)/lib/python2.7/site-packages/_scrypt.so dist/bitmask/
	cp ../../src/leap/bitmask/core/bitmaskd.tac dist/bitmask
	mkdir dist/bitmask/leap
	cp -r $(VIRTUAL_ENV)/lib/python2.7/site-packages/leap/bitmask_js/  dist/bitmask/leap
	mv dist/bitmask lib && mkdir dist/bitmask && mv lib dist/bitmask/lib
	cd ../launcher && make
	cp ../launcher/bitmask dist/bitmask/

clean:
	rm -rf dist build

