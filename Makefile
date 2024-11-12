deps:
    pyenv install -s 3.9.15
	PYENV_VERSION=3.9.15 python -m venv snos-env
	. cairo-vm-env/bin/activate ; \
	pip install -r requirements.txt ; \

