#!/usr/bin/env bash
set -euo pipefail

# usage: ./build.sh [build-dir]
BUILD_DIR=${1:-build}
CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE:-Release}

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

declare -a CMAKE_ARGS
CMAKE_ARGS+=("-DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}")

uname_s=$(uname -s)
case "$uname_s" in
	Darwin)
		if command -v brew >/dev/null 2>&1; then
			ZLIB_PREFIX=$(brew --prefix zlib 2>/dev/null || true)
		fi
		: "${ZLIB_PREFIX:=/opt/homebrew/opt/zlib}"
		if [ -d "$ZLIB_PREFIX" ]; then
			CMAKE_ARGS+=("-DCMAKE_PREFIX_PATH=${ZLIB_PREFIX}")
		fi
		;;
	Linux)
		# linux is the greatest OS --- IGNORE ---
		;;
	MINGW*|MSYS*|CYGWIN*)
        # no idea if this works. for now, its commented out
		#if [ -n "${VCPKG_ROOT:-}" ] && [ -f "$VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake" ]; then
		#	CMAKE_ARGS+=("-DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake")
		#fi
		;;
	*)
		# what os do you have bro? rely on default discovery
		;;
esac

echo "Configuring with: cmake .. ${CMAKE_ARGS[*]}"
cmake .. "${CMAKE_ARGS[@]}"

echo "Building (${CMAKE_BUILD_TYPE})..."
cmake --build . --config "${CMAKE_BUILD_TYPE}"

if [ "${RUN_TESTS:-0}" = "1" ]; then
	ctest --output-on-failure -C "${CMAKE_BUILD_TYPE}"
fi