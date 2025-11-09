#!/bin/sh
set -e

SCRIPT_DIR=$(dirname $0)
ENV_DIR=${SCRIPT_DIR}/venv

echo "Creating virtual env dir..."
python3 -m venv ${ENV_DIR}
echo "Done"

. ${ENV_DIR}/bin/activate

echo "Installing necessary modules..."
pip install pytest psutil
echo "Done"

