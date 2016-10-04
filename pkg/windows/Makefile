.PHONY: all pkg installer openvpn pyinstaller
all:
	docker-compose build
	$(MAKE) bundle

bundle:
	# Disabling openvpn for now...
	# $(MAKE) openvpn
	$(MAKE) pyinstaller
	$(MAKE) installer

pyinstaller:
	docker-compose run --rm pyinstaller

openvpn:
	docker-compose run --rm openvpn

installer:
	docker-compose run --rm installer


# variant to keep the containers around
# and save some bandwith

pyinstaller_keep:
	docker-compose run pyinstaller

openvpn_keep:
	docker-compose run openvpn

installer_keep:
	docker-compose run installer

clean:
	docker rmi windows_pyinstaller
	docker rmi windows_openvpn
	docker rmi windows_installer
	rm -rf ../../dist/*.exe
	rm -rf ../../build/*
