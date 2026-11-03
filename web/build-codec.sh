#!/bin/sh
# Compile only the vendored MIT container tool; no firmware or samples enter this build.
set -eu
cd "$(dirname "$0")/.."
EMCC=${EMCC:-emcc}
version=$("$EMCC" --version | head -1)
case "$version" in *'4.0.22'*) ;; *) echo 'Emscripten 4.0.22 is required' >&2; exit 1;; esac
"$EMCC" -O2 -std=c11 -Wall -Wextra \
  -ffile-prefix-map="$PWD"=. -fdebug-prefix-map="$PWD"=. \
  port/tools/elektron-firmware-tool/*.c \
  -sMODULARIZE=1 -sEXPORT_ES6=1 -sEXPORT_NAME=createFirmwareCodec \
  -sENVIRONMENT=web,worker,node -sALLOW_MEMORY_GROWTH=1 \
  -sINITIAL_MEMORY=134217728 -sMAXIMUM_MEMORY=536870912 \
  -sEXPORTED_RUNTIME_METHODS=FS,callMain -sINVOKE_RUN=0 \
  -o web/codec-native.mjs
cp port/tools/elektron-firmware-tool/LICENSE web/codec-LICENSE.txt
