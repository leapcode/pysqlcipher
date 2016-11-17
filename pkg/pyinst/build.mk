# This makefile should be called from the topmost bitmask folder
#
bundle: bundle_clean
	pyinstaller -y pkg/pyinst/app.spec
	cp $(VIRTUAL_ENV)/lib/python2.7/site-packages/_scrypt.so $(DIST)
	cp src/leap/bitmask/core/bitmaskd.tac $(DIST)
	mkdir $(DIST)/leap
	mkdir -p $(DIST)/leap/soledad/common/l2db/backends
	cp $(VIRTUAL_ENV)/lib/python2.7/site-packages/leap/soledad/common/l2db/backends/dbschema.sql $(DIST)/leap/soledad/common/l2db/backends/
	cp -r $(VIRTUAL_ENV)/lib/python2.7/site-packages/leap/bitmask_js/  $(DIST)/leap
	mv $(DIST) _bundlelib && mkdir $(DIST_VERSION) && mv _bundlelib $(DIST_VERSION)/lib
	cd pkg/launcher && make
	cp pkg/launcher/bitmask $(DIST_VERSION)

bundle_win:
	pyinstaller -y pkg/pyinst/app.spec
	cp ${VIRTUAL_ENV}/Lib/site-packages/_scrypt.pyd $(DIST)
	cp ${VIRTUAL_ENV}/Lib/site-packages/zmq/libzmq.pyd $(DIST)
	cp src/leap/bitmask/core/bitmaskd.tac $(DIST)

bundle_gpg:
	# TODO build it in a docker container!
	mkdir -p $(DIST_VERSION)/apps/mail
	cp /usr/bin/gpg $(DIST_VERSION)/apps/mail/

bundle_tar:
	cd dist/ && tar cvzf Bitmask.$(NEXT_VERSION).tar.gz bitmask-$(NEXT_VERSION)

bundle_sign:
	gpg2 -a --sign --detach-sign dist/Bitmask.$(NEXT_VERSION).tar.gz 

bundle_upload:
	rsync --rsh='ssh' -avztlpog --progress --partial dist/Bitmask.$(NEXT_VERSION).* downloads.leap.se:./

bundle_clean:
	rm -rf "dist" "build"

