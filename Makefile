all:
	@echo select target

clean:
	rm -rf build dist psrt.egg-info

pub: clean sdist upload

dist:
	python3 setup.py sdist

upload:
	twine upload dist/*
