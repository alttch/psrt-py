VERSION=0.0.4

all:
	@echo select target

clean:
	rm -rf build dist psrt.egg-info

pub: clean sdist upload

sdist:
	python3 setup.py sdist

upload:
	twine upload dist/*

ver:
	find . -type f -name "*.py" -exec \
			sed -i "s/^__version__ = .*/__version__ = '${VERSION}'/g" {} \;
