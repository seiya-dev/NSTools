#!/bin/bash

SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
cd "$SCRIPTPATH/.."

cp -r ./py/* ./build
cp LICENSE.md ./build
cp README.md ./build
python3 -m build build
