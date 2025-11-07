#!/bin/sh
set -e

SCRIPT_DIR=$(dirname $0)
ENV_DIR=${SCRIPT_DIR}/venv

echo "#Activating test environment..."
. ${ENV_DIR}/bin/activate
echo "Done"

echo "#Running tests..."
pytest -v ${SCRIPT_DIR}/test_proxy-dns.py
echo "Done"