#!/usr/bin/env bash
set -e

# Run the Python unit tests against the freshly built libhasher, if any
# (.so on Linux, .dylib on macOS). hasher.load_library() falls back to
# loading the library by bare name, so point the dynamic linker at .libs.
for ext in so dylib; do
  if [ -e src/lib/.libs/libhasher.$ext ]; then
    LIBS=$(realpath src/lib/.libs)
    pushd python
    LD_LIBRARY_PATH=$LIBS:$LD_LIBRARY_PATH \
    DYLD_LIBRARY_PATH=$LIBS:$DYLD_LIBRARY_PATH \
      python3 -m unittest -v
    popd
    exit 0
  fi
done

echo "src/lib/.libs/libhasher.{so,dylib} not found; skipping Python tests"
