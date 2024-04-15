#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2024 Philip Eklöf
#
# SPDX-License-Identifier: MIT

syntax()
{
  local cmd env_lines n text v

  # No need for `fold` and `sed` when it can be done using bash...
  env_lines=('')
  n='0'
  for v in "${_GLOBALS[@]}"; do
    if [[ $v =~ ^_ ]]; then
      continue
    fi
    if [ $((${#env_lines[n]} + 2 + ${#v})) -gt '79' ]; then
      env_lines["$n"]+=','
      ((n += 1))
    fi
    env_lines["$n"]+=", $v"
  done
  printf -v env_lines '  %s\n' "${env_lines[@]#, }" # var re-use, but it's fine

  cmd="${0##*/}"
  readarray -t text << EOF
usage: ${cmd%.sh} <arg>..

This tool uses python3 and pip to build a wheel of a local python project. The
wheel build is performed without isolation (i.e. all build dependencies must
already be installed in the system), and the index is disabled (no outgoing
requests to PyPi). Once installed, the wheel is installed into the user install
directory, verified that it can be imported, optionally tested using
pytest/unittest, and then uninstalled again.

The wheel may also be requested to be copied/extracted into a chosen directory.

Primarily meant to be used in clean CI environments prior to distro packaging.

--working-dir <path>
Change to this directory before performing any operations.

--prefix <path>
<path>/bin will be inserted as the first entry into the PATH, where an
executable for python3 will be expected to be found. Required option.

--target-dir <path>
Triggers unpacking of the wheel, where the specified directory is used in a
"DESTDIR" sense. The prefix and module path will be appended to this path.

--modules-path <relative path>
Use this module path rather than 'lib/python<version>/site-packages' when
unpacking the wheel.

--wheel-dir <path>
Copy the wheel into this directory.

--pytest
Execute pytest after the wheel has been built and installed.

--unittest
Execute unittest after the wheel has been built and installed.

--pre-build-cmd <cmd>
--post-build-cmd <cmd>
--pre-install-cmd <cmd>
--post-install-cmd <cmd>
--pre-uninstall-cmd <cmd>
--post-uninstall-cmd <cmd>
Execute a command via bash -c <cmd> at a certain stage, with env:
$env_lines
EOF

  printf '%s\n' "${text[@]:0:$((${#text[@]} - 1))}" # skip last empty item

  exit 0
}

msg()
{
  printf '%s\n' "$1" >&2
}

error()
{
  msg "(error) $1"
}

info()
{
  msg "(info) $1"
}

die()
{
  error "$1"
  _EXPECTED_EXIT='yes'
  exit 1
}

run()
{
  info "[exec] ${*@Q}"
  rc='0'
  "$@" || rc="$?"
  [ "$rc" == '0' ] ||
    die "Failed executing command (exit code ${rc@Q}): ${*@Q}"
}

exit_trap()
{
  if [ -z "$_EXPECTED_EXIT" ]; then
    error 'Unexpected exit due to non-zero exit status.'
  fi

  if [ -n "$TMP_DIR" ]; then
    rm -rf -- "$TMP_DIR"
  fi
  if [ -n "$WHEEL_INSTALLED" ]; then
    if ! out="$(wheel_uninstall 2>&1)"; then
      error "Failed uninstalling wheel during rollback with output ${out@Q}."
    fi
  fi
}

check_python()
{
  local actual expected out

  if [ -n "$PREFIX" ]; then
    PATH="$PREFIX/bin:$PATH"
  fi

  hash 'python3' 2>&- ||
    die "python3 not found in PATH ${PATH@Q}."

  actual="$(hash -t 'python3' 2>&-)" ||
    die "python3 not found in PATH ${PATH@Q} (is it a shell function?)."

  if [ -n "$PREFIX" ]; then
    expected="$PREFIX/bin/python3"
    [ "$actual" == "$expected" ] ||
      die "Found python3 at ${actual@Q}, expecting ${expected@Q}, due to given \
prefix."
  fi

  out="$(run python3 --version)"
  [[ $out =~ ^Python\ (3\.[0-9]+)\. ]] ||
    die "Unexpected python3 version output ${out@Q}."

  PYTHON_VERSION="${BASH_REMATCH[1]}"
}

check_module_import()
{
  local data f module out

  module="$1"

  f="$TMP_DIR/check_module_import/script.py"
  mkdir -p -- "${f%/*}"
  readarray -t data << 'EOF'
import sys

try:
    __import__(sys.argv[1])
except ModuleNotFoundError:
    print("not found")
else:
    print("imported")
EOF
  printf '%s\n' "${data[@]}" > "$f"

  out="$(run python3 "$f" "$module")"
  rm -- "$f"

  case "$out" in
    'imported')
      _MODULE_IMPORT_SUCCESS='yes'
      ;;
    'not found')
      _MODULE_IMPORT_SUCCESS=''
      ;;
    *)
      die "Unknown error while checking if ${module@Q} is already installed \
(output: ${out@Q})"
      ;;
  esac
}

hook_cmd_run()
{
  [ -n "$2" ] || return 0
  info "About to execute hook command for stage ${1@Q}."
  (
    for v in "${_GLOBALS[@]}"; do
      # shellcheck disable=2163 # This does not export 'v'
      [[ $v =~ ^_ ]] || export "$v"
    done
    export STAGE="$1"
    run bash -c "$2"
  )
  info "Successfully executed hook command for stage ${1@Q}."
}

wheel_build()
{
  local d f fn matches rgx

  d="$TMP_DIR/wheel"
  mkdir -p -- "$d"

  run python3 -m pip wheel \
    --no-build-isolation \
    --no-cache-dir \
    --no-deps \
    --no-index \
    --wheel-dir "$d" \
    .

  matches=("$d"/*.whl)
  if [ "${#matches[@]}" == '0' ]; then
    die 'Unexpectedly, no wheel was built.'
  elif [ "${#matches[@]}" -gt '1' ]; then
    ls -al -- "$d"
    printf '\n' >&2
    die "Expected a single wheel to have been built, found ${#matches[@]}."
  fi

  f="${matches[0]}"
  fn="${f##*/}"

  rgx='^([0-9a-z]([0-9a-z_]*[0-9a-z])?)-'
  [[ $fn =~ $rgx ]] ||
    die "Unexpected wheel filename ${fn@Q}, not matching regex ${rgx@Q}."

  WHEEL_NAME="${BASH_REMATCH[1]}"
  WHEEL_FILE="$f"
}

wheel_install()
{
  run python3 -m pip install \
    --break-system-packages \
    --no-cache-dir \
    --no-deps \
    --no-index \
    --user \
    -- "$WHEEL_FILE"

  WHEEL_INSTALLED='yes'
}

wheel_uninstall()
{
  WHEEL_INSTALLED='' # unset it prior to uninstall to not trigger exit trap
  run python3 -m pip uninstall --no-cache-dir --yes -- "$WHEEL_NAME"
}

set -eupo pipefail
shopt -s nullglob
shopt -s inherit_errexit

unset _GLOBALS
_GLOBALS=(
  'MODULES_PATH'
  'MODULES_TARGET_DIR'
  'PREFIX'
  'STAGE'
  'TARGET_DIR'
  'TMP_DIR'
  'WHEEL_DIR'
  'WHEEL_FILE'
  'WHEEL_INSTALLED'
  'WHEEL_NAME'
  'WORK_DIR'
  '_EXPECTED_EXIT'
  '_MODE_PYTEST'
  '_MODE_UNITTEST'
  '_MODULE_IMPORT_SUCCESS'
  '_POST_BUILD_CMD'
  '_POST_INSTALL_CMD'
  '_POST_UNINSTALL_CMD'
  '_PRE_BUILD_CMD'
  '_PRE_INSTALL_CMD'
  '_PRE_UNINSTALL_CMD'
)
for v in "${_GLOBALS[@]}"; do
  unset "$v"
  eval "$v=''"
done
unset v

while [ -n "${1+set}" ]; do
  case "$1" in
    '--help')
      syntax
      ;;
    '--modules-path')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      MODULES_PATH="$2"
      shift 2
      ;;
    '--pre-build-cmd')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      _PRE_BUILD_CMD="$2"
      shift 2
      ;;
    '--pre-install-cmd')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      _PRE_INSTALL_CMD="$2"
      shift 2
      ;;
    '--pre-uninstall-cmd')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      _PRE_UNINSTALL_CMD="$2"
      shift 2
      ;;
    '--post-build-cmd')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      _POST_BUILD_CMD="$2"
      shift 2
      ;;
    '--post-install-cmd')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      _POST_INSTALL_CMD="$2"
      shift 2
      ;;
    '--post-uninstall-cmd')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      _POST_UNINSTALL_CMD="$2"
      shift 2
      ;;
    '--prefix')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      PREFIX="$(readlink -m -- "$2")"
      shift 2
      ;;
    '--pytest')
      _MODE_PYTEST='yes'
      shift
      ;;
    '--target-dir')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      TARGET_DIR="$(readlink -m -- "$2")"
      shift 2
      ;;
    '--unittest')
      _MODE_UNITTEST='yes'
      shift
      ;;
    '--wheel-dir')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      WHEEL_DIR="$(readlink -m -- "$2")"
      shift 2
      ;;
    '--working-dir')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      WORK_DIR="$(readlink -m -- "$2")"
      shift 2
      ;;
    *)
      die "Argument ${1@Q} is not recognized, see --help."
      ;;
  esac
done

[ -n "$PREFIX" ] ||
  die 'Argument --prefix is required.'
[ -d "$PREFIX" ] ||
  die "Prefix directory ${PREFIX@Q} could not be found."

check_python

if [ -n "$TARGET_DIR" ]; then
  hash unzip 2>&- ||
    die "'unzip' command not found, required with --target-dir."
  if [ -n "$MODULES_PATH" ]; then
    unset rgx
    rgx='^[^/]+(/[^/]+)*'
    [[ $MODULES_PATH =~ $rgx ]] ||
      die "Modules path ${MODULES_PATH@Q} not matching regex ${rgx@Q}."
    rgx='(^|/)\.\.?(/|$)'
    if [[ $MODULES_PATH =~ $rgx ]]; then
      die "Modules path ${MODULES_PATH@Q} contains relative path component(s)."
    fi
    unset rgx
  else
    MODULES_PATH="lib/python$PYTHON_VERSION/site-packages"
  fi

  TARGET_DIR+="$PREFIX"
  MODULES_TARGET_DIR="$TARGET_DIR/$MODULES_PATH"
  run mkdir -p -- "$MODULES_TARGET_DIR"
fi

if [ -n "$WHEEL_DIR" ]; then
  run mkdir -p -- "$WHEEL_DIR"
fi

TMP_DIR="$(run mktemp -d)"
trap exit_trap EXIT

if [ -n "$WORK_DIR" ]; then
  cd -- "$WORK_DIR"
fi

hook_cmd_run 'pre-build' "$_PRE_BUILD_CMD"
info 'Building wheel...'
wheel_build
info 'Successfully built wheel.'
hook_cmd_run 'post-build' "$_POST_BUILD_CMD"

info 'Verifiying that wheel is not already installed...'
check_module_import "$WHEEL_NAME"
[ -z "$_MODULE_IMPORT_SUCCESS" ] ||
  die "Wheel ${WHEEL_NAME@Q} is already installed in this python environment."
info 'Wheel is not already installed.'

hook_cmd_run 'pre-install' "$_POST_INSTALL_CMD"
info 'Installing wheel...'
wheel_install
info 'Successfully installed wheel.'
hook_cmd_run 'post-install' "$_POST_INSTALL_CMD"

info 'Verifiying that installed wheel can be imported as a module...'
check_module_import "$WHEEL_NAME"
[ -n "$_MODULE_IMPORT_SUCCESS" ] ||
  die "Unexpectedly failed to import module ${WHEEL_NAME@Q}."
info 'Successfully imported module.'

if [ -n "$_MODE_PYTEST" ]; then
  info 'Running tests using pytest...'
  run python3 -m pytest -v
  info 'Successfully run tests using pytest.'
fi

if [ -n "$_MODE_UNITTEST" ]; then
  info 'Running tests using unittest...'
  run python3 -m unittest discover tests -v
  info 'Successfully run tests using unittest.'
fi

hook_cmd_run 'pre-uninstall' "$_POST_UNINSTALL_CMD"
info 'Uninstall wheel again...'
wheel_uninstall
info 'Successfully uninstalled wheel.'
hook_cmd_run 'post-uninstall' "$_POST_UNINSTALL_CMD"

if [ -n "$TARGET_DIR" ]; then
  info "Unpacking wheel into ${MODULES_TARGET_DIR@Q}..."
  run unzip -o -- "$WHEEL_FILE" -d "$MODULES_TARGET_DIR/"
  info 'Successfully unpacked wheel.'
fi

if [ -n "$WHEEL_DIR" ]; then
  info "Copying wheel into ${WHEEL_DIR@Q}..."
  run cp -a -- "$WHEEL_FILE" "$WHEEL_DIR/"
  info 'Successfully copied wheel.'
fi

info 'All done.'

rm -rf -- "$TMP_DIR"
trap '' EXIT
