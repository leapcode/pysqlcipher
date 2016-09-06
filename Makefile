clean:
	find . -type f -name "*.py[co]" -delete
	find . -type d -name "__pycache__" -delete

dev-mail:
	pip install -e '.[mail]'
	pip install -e www

dev-all:
	pip install -e '.[all]'

uninstall:
	pip uninstall leap.bitmask
