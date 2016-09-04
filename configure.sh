#!/bin/bash

PYTHON_VERSION=${1:-3.4}

# system package requirements:
#   - dev-lang/python (appropriate version)
#   - dev-python/virtualenv


fatal() {
  message="$1";

  echo "ERROR: $message"
  exit 1
}


[[ ! -x /usr/bin/python${PYTHON_VERSION} ]] && fatal "Please install python${PYTHON_VERSION} or use ./configure.sh PYTHON_VERSION"

# setup python modules
if [[ ! -d .virtualenv ]]
then
    virtualenv --python=python${PYTHON_VERSION} .virtualenv || fatal 'Failed to create virtualenv'
fi

if [[ ! -h python_modules ]]
then
    ln -s .virtualenv/lib/python${PYTHON_VERSION}/site-packages python_modules || fatal 'Failed to create symlink "python_modules"'
fi

[[ ! -r .virtualenv/bin/activate ]] && fatal 'Cannot activate virtualenv'
if [[ -r .virtualenv/bin/activate ]]
then
    . .virtualenv/bin/activate
fi

pip install --upgrade pip || fatal 'Cannot upgrade pip'
pip install --upgrade python-dateutil
