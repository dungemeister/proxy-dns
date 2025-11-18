#!/bin/sh
set -e

#Parsing args
SCRIPT_DIR=$(dirname $0)
REBUILD=$1
#Prepare vars
BUILD_DIR="build"
TEST_DIR=${SCRIPT_DIR}/${BUILD_DIR}/unit_tests
TESTS_ARRAY="test_cache test_server test_queue"

cd ${SCRIPT_DIR}
if [ "$REBUILD" != "" ]; then
    make tests
fi

for test in ${TESTS_ARRAY}; do
    echo "#Starting unit test ${test}"
    ${TEST_DIR}/${test}
done
