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
    if [[ $v =~ ^[_@=] ]]; then
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
Triggers extraction of the wheel, where the specified directory is used in a
"DESTDIR" sense.

--modules-path <relative path>
Extract the modules into this path, relative to the target dir.
Default: <prefix>/lib/python<version>/site-packages

--entrypoints-path <path>
Generate entrypoints into this path, relative to the target dir.
Default: <prefix>/bin

--wheel-dir <path>
Copy the wheel into this directory.

--expect-modules <module1,moduleN,..>
Expect these comma-separated module names in the wheel, which will be imported
one by one, during verification. Defaults to the name of the wheel.

--extract-modules <module1,moduleN,..>
Extract only these modules (defaults to the ones expected).

--expect-files <file1,fileN,..>
Expect these extra non-module files/dirs in the wheel's top directory.

--extract-files <file1,fileN,..>
Extract only these files/dirs (defaults to the ones expected).

--expect-entrypoints <entrypoint,entrypointN,..>
Expect these entrypoints to be defined in the wheel.

--generate-entrypoints <entrypoint,entrypointN,..>
Generate only these entrypoints (defaults to the ones expected).

--build-only
Only build and optionally extract the wheel, do not verify or test the wheel.

--no-verify-import
Verify contents of the wheel, but do not try to install and import it.

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
--post-extraction-cmd <cmd>
--post-entrypoint-generate-cmd <cmd>
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

exit_trap()
{
  local d paths

  if [ -z "$_EXPECTED_EXIT" ]; then
    error 'Unexpected exit due to non-zero exit status.'
  fi

  if [ -n "$TMP_DIR" ]; then
    rm -rf -- "$TMP_DIR"
  fi

  paths=(
    "${ENTRYPOINTS_TARGET_DIR-}"
    "${MODULES_TARGET_DIR-}"
    "${WHEEL_DIR-}"
  )
  for d in "${paths[@]}"; do
    [ -n "$d" ] || continue
    rmdir -p --ignore-fail-on-non-empty -- "$d" 2>&- || :
  done

  if [ -n "$WHEEL_INSTALLED" ]; then
    if ! out="$(wheel_uninstall 2>&1)"; then
      error "Failed uninstalling wheel during rollback with output ${out@Q}."
    fi
  fi
}

# helper functions below
csv_read()
{
  local csv_val dst_var val values

  dst_var="$1"
  csv_val="$2"

  values=()
  while IFS='' read -d, -r val; do
    [ -n "$val" ] || continue
    values+=("$val")
  done < <(printf '%s,' "$csv_val")

  eval "$dst_var"='("${values[@]}")'
}

run()
{
  info "[exec] ${*@Q}"
  rc='0'
  "$@" || rc="$?"
  [ "$rc" == '0' ] ||
    die "Failed executing command (exit code ${rc@Q}): ${*@Q}"
}

# main functions below
check_arg_filename_items()
{
  local arg arg_name

  arg_name="$1"
  shift

  [ "$#" -ge '1' ] ||
    die "Argument ${arg_name@Q} requires a non-empty comma-separated value."

  for arg; do
    if [[ $arg =~ / ]]; then
      die "Argument ${arg_name@Q} (${*@Q}) must not contain any / characters."
    fi
  done
}

check_arg_valid_path()
{
  local description path rgx

  path="$1"
  description="$2"

  rgx='^[^/]+(/[^/]+)*'
  [[ $path =~ $rgx ]] ||
    die "$description path ${path@Q} not matching regex ${rgx@Q}."

  rgx='(^|/)\.\.?(/|$)'
  if [[ $path =~ $rgx ]]; then
    die "$description path ${path@Q} contains relative path component(s)."
  fi
}

check_arg_list_a_contains_all_b_list_items()
{
  local a_count a_index a_items a_name b_count b_items b_name item missing

  a_name="$1"
  b_name="$2"
  a_count="$3"
  b_count="$4"
  shift 4

  [ "$#" == "$((a_count + b_count))" ] ||
    die "BUG: a_count(${a_count@Q}) b_count(${b_count@Q}) argc($#)"

  a_items=("${@:1:$a_count}")
  declare -A a_index=()
  for item in "${a_items[@]}"; do
    a_index["$item"]='set'
  done
  shift "$a_count"

  b_items=("$@")

  missing=()
  for item in "${b_items[@]}"; do
    [ -n "${a_index["$item"]-}" ] ||
      missing+=("$item")
  done

  [ "${#missing[@]}" == '0' ] ||
    die "All items in argument $b_name (${b_items[*]@Q}) must also be set for \
$a_name (${a_items[*]@Q}), missing: ${missing[*]@Q}"
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
except ModuleNotFoundError as e:
    print("ModuleNotFoundError")
    print(e)
EOF
  printf '%s\n' "${data[@]}" > "$f"

  out="$(run python3 "$f" "$module")"
  rm -- "$f"

  _MODULE_IMPORT_ERROR=''
  [ -n "$out" ] || return 0

  [ "${out%%$'\n'*}" == 'ModuleNotFoundError' ] ||
    die "Importing module ${module@Q} generated unexpected output:"$'\n'"$out"

  _MODULE_IMPORT_ERROR="${out#*$'\n'}"
}

hook_cmd_run()
{
  [ -n "$2" ] || return 0
  info "About to execute hook command for stage ${1@Q}."
  (
    for v in "${_GLOBALS[@]}"; do
      # shellcheck disable=2163 # This does not export 'v'
      [[ $v =~ ^[_@=] ]] || export "$v"
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
    die 'Build succeeded, but no resulting wheel could be found.'
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

wheel_entrypoints_file_parse()
{
  local data f found line out rgx s

  f="$TMP_DIR/wheel_entrypoint_generate.py"
  mkdir -p -- "${f%/*}"
  readarray -t data << 'EOF'
import sys
import zipfile
with zipfile.ZipFile(sys.argv[1], 'r') as zh:
    try:
        print(zh.read(f"{sys.argv[2]}/entry_points.txt").decode())
    except KeyError:
        pass
EOF
  printf '%s\n' "${data[@]}" > "$f"

  out="$(run python3 "$f" "$WHEEL_FILE" "$_WHEEL_DIST_INFO_DIRNAME")"
  rm -- "$f"

  if [ -z "$out" ]; then
    _ENTRYPOINTS_PARSE_ERROR='No entrypoints data found in wheel.'
    return 0
  fi

  found=''
  s='[:space:]'
  rgx="^[$s]*([^$s/]+)[$s]*=[$s]*([^$s:]+:[^$s]+)[$s]*$"
  _ENTRYPOINTS=()
  while read -r line; do
    if [ -z "$found" ]; then
      [ "$line" == '[console_scripts]' ] || continue
      found='yes'
    else
      if [[ $line =~ ^\[ ]]; then
        break
      elif [[ $line =~ $rgx ]]; then
        _ENTRYPOINTS["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
      fi
    fi
  done <<< "$out"

  if [ -z "$found" ]; then
    _ENTRYPOINTS_PARSE_ERROR="No console_scripts section found in wheel's \
entrypoints data."
    return 0
  fi

  if [ "${#_ENTRYPOINTS[@]}" == '0' ]; then
    _ENTRYPOINTS_PARSE_ERROR="Found console_scripts section in wheel's \
entrypoints data, but no (valid) entrypoints."
    return 0
  fi
}

wheel_entrypoints_parse()
{
  local entrypoints expected found missing unexpected

  wheel_entrypoints_file_parse

  entrypoints=("${!_ENTRYPOINTS[@]}") # as ${!_ENTRYPOINTS[*]@Q} is broken

  if [ "${#_ENTRYPOINTS_EXPECTED[@]}" == '0' ]; then
    if [ "${#entrypoints[@]}" == '0' ]; then
      info 'No entrypoints found in wheel and none were expected either.'
      return 0
    else
      die "No entrypoints expected in wheel, but found: ${entrypoints[*]@Q}"
    fi
  fi

  if [ -n "${_ENTRYPOINTS_PARSE_ERROR}" ]; then
    die "$_ENTRYPOINTS_PARSE_ERROR"
  fi

  declare -A expected=()
  for f in "${_ENTRYPOINTS_EXPECTED[@]}"; do
    expected["$f"]='set'
  done
  declare -A found=()
  unexpected=()
  for f in "${entrypoints[@]}"; do
    if [ -z "${expected["$f"]-}" ]; then
      unexpected+=("$f")
    else
      found["$f"]='set'
    fi
  done

  if [ "${#unexpected[@]}" -ge '1' ]; then
    die "Unexpected entrypoint(s) found in wheel: ${unexpected[*]@Q} \
(expected: ${_ENTRYPOINTS_EXPECTED[*]@Q})"
  fi

  missing=()
  for f in "${_ENTRYPOINTS_EXPECTED[@]}"; do
    [ -n "${found["$f"]-}" ] || missing+=("$f")
  done
  [ "${#missing[@]}" == '0' ] ||
    die "Missing expected entrypoint(s) in wheel: ${missing[*]@Q}"

  info "All expected entrypoints found in wheel: ${_ENTRYPOINTS_EXPECTED[*]@Q}"
}

wheel_entrypoints_generate()
{
  local data f function module name

  for name in "${_ENTRYPOINTS_GENERATE[@]}"; do
    module="${_ENTRYPOINTS["$name"]%%:*}"
    function="${_ENTRYPOINTS["$name"]#*:}"

    readarray -t data << EOF
#!$PREFIX/bin/python3
import sys
from $module import $function
if __name__ == '__main__':
    sys.exit($function())
EOF

    f="$ENTRYPOINTS_TARGET_DIR/$name"
    info "Generating entrypoint ${f@Q}."
    printf '%s\n' "${data[@]}" > "$f"
    chmod -- 0755 "$f"
  done
}

wheel_extract()
{
  local data f

  f="$TMP_DIR/wheel_extract.py"
  mkdir -p -- "${f%/*}"
  readarray -t data << 'EOF'
import sys
import zipfile
files = set(sys.argv[3:])
with zipfile.ZipFile(sys.argv[1], 'r') as zh:
    for info in zh.infolist():
        name = info.filename.split("/")[0]
        if name in files or name.endswith(".dist-info"):
            zh.extract(info, sys.argv[2])
EOF
  printf '%s\n' "${data[@]}" > "$f"

  run python3 "$f" "$WHEEL_FILE" "$MODULES_TARGET_DIR" \
    "${_FILES_EXTRACT[@]}" "${_MODULES_EXTRACT[@]}"
  rm -- "$f"
}

wheel_install()
{
  run python3 -m pip install \
    --break-system-packages \
    --no-cache-dir \
    --no-deps \
    --no-index \
    --no-warn-script-location \
    --user \
    -- "$WHEEL_FILE"

  WHEEL_INSTALLED='yes'
}

wheel_uninstall()
{
  WHEEL_INSTALLED='' # unset it prior to uninstall to not trigger exit trap
  run python3 -m pip uninstall --no-cache-dir --yes -- "$WHEEL_NAME"
}

wheel_verify_content()
{
  local data dist_info expected expected_list f found missing out unexpected

  f="$TMP_DIR/wheel_verify_content.py"
  mkdir -p -- "${f%/*}"
  readarray -t data << 'EOF'
import sys
import zipfile
with zipfile.ZipFile(sys.argv[1], 'r') as zh:
    print("\n".join(set([f.split("/")[0] for f in zh.namelist()])))
EOF
  printf '%s\n' "${data[@]}" > "$f"

  out="$(run python3 "$f" "$WHEEL_FILE")"
  rm -- "$f"

  expected_list=("${_MODULES_EXPECTED[@]}" "${_FILES_EXPECTED[@]}")
  declare -A expected=()
  for f in "${expected_list[@]}"; do
    expected["$f"]='set'
  done
  dist_info=()
  declare -A found=()
  unexpected=()
  while read -r f; do
    if [[ $f =~ \.dist-info$ ]]; then
      dist_info+=("$f")
    elif [ -z "${expected["$f"]-}" ] && [ -z "${expected["${f%.py}"]-}" ]; then
      unexpected+=("$f")
    else
      if [[ $f =~ \.py$ ]]; then
        _MODULES_EXTRACT+=("$f")
      fi
      found["$f"]='set'
    fi
  done <<< "$out"

  if [ "${#dist_info[@]}" == '0' ]; then
    die 'No *.dist-info items found in wheel.'
  elif [ "${#dist_info[@]}" -gt '1' ]; then
    die "Multiple *.dist-info items found in wheel: ${dist_info[*]@Q}"
  fi
  if [ "${#unexpected[@]}" -ge '1' ]; then
    die "Unexpected items found in wheel: ${unexpected[*]@Q} (expected: \
${expected_list[*]@Q})"
  fi

  missing=()
  for f in "${_MODULES_EXPECTED[@]}" "${_FILES_EXPECTED[@]}"; do
    if [ -z "${found["$f"]-}" ] && [ -z "${found["$f.py"]-}" ]; then
      missing+=("$f")
    fi
  done
  [ "${#missing[@]}" == '0' ] ||
    die "Missing expected item(s) in wheel: ${missing[*]@Q}"

  _WHEEL_DIST_INFO_DIRNAME="${dist_info[0]}"

  info "All expected modules and files found in wheel: ${expected_list[*]@Q}"
}

set -eupo pipefail
shopt -s nullglob
shopt -s inherit_errexit

unset _GLOBALS
_GLOBALS=(
  'ENTRYPOINTS_PATH'
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
  '_BUILD_ONLY'
  '_ENTRYPOINTS_PARSE_ERROR'
  '_EXPECTED_EXIT'
  '_MODE_PYTEST'
  '_MODE_UNITTEST'
  '_MODULE_IMPORT_ERROR'
  '_POST_BUILD_CMD'
  '_POST_ENTRYPOINT_GENERATE_CMD'
  '_POST_EXTRACTION_CMD'
  '_POST_INSTALL_CMD'
  '_POST_UNINSTALL_CMD'
  '_PRE_BUILD_CMD'
  '_PRE_INSTALL_CMD'
  '_PRE_UNINSTALL_CMD'
  '_VERIFY_IMPORT'
  '_WHEEL_DIST_INFO_DIRNAME'
  '@_ENTRYPOINTS_EXPECTED'
  '@_ENTRYPOINTS_GENERATE'
  '@_FILES_EXPECTED'
  '@_FILES_EXTRACT'
  '@_MODULES_EXPECTED'
  '@_MODULES_EXTRACT'
  '=_ENTRYPOINTS'
)
for v in "${_GLOBALS[@]}"; do
  if [ "${v:0:1}" == '@' ]; then
    unset "${v:1}"
    eval "${v:1}=()"
  elif [ "${v:0:1}" == '=' ]; then
    unset "${v:1}"
    eval declare -A "${v:1}=()"
  else
    unset "$v"
    eval "$v=''"
  fi
done
unset v

_VERIFY_IMPORT='yes'

while [ -n "${1+set}" ]; do
  case "$1" in
    '--help')
      syntax
      ;;
    '--build-only')
      _BUILD_ONLY='yes'
      shift
      ;;
    '--expect-entrypoints')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      csv_read '_ENTRYPOINTS_EXPECTED' "$2"
      check_arg_filename_items "$1" "${_ENTRYPOINTS_EXPECTED[@]}"
      shift 2
      ;;
    '--expect-files')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      csv_read '_FILES_EXPECTED' "$2"
      check_arg_filename_items "$1" "${_FILES_EXPECTED[@]}"
      shift 2
      ;;
    '--expect-modules')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      csv_read '_MODULES_EXPECTED' "$2"
      check_arg_filename_items "$1" "${_MODULES_EXPECTED[@]}"
      shift 2
      ;;
    '--extract-files')
      if [ -n "${2-}" ]; then
        csv_read '_FILES_EXTRACT' "$2"
        check_arg_filename_items "$1" "${_FILES_EXTRACT[@]}"
      elif [ -z "${2-unset}" ]; then
        _FILES_EXTRACT=('/NOOP')
      else
        die "Argument ${1@Q} requires a value."
      fi
      shift 2
      ;;
    '--extract-modules')
      if [ -n "${2-}" ]; then
        csv_read '_MODULES_EXTRACT' "$2"
        check_arg_filename_items "$1" "${_MODULES_EXTRACT[@]}"
      elif [ -z "${2-unset}" ]; then
        _MODULES_EXTRACT=('/NOOP')
      else
        die "Argument ${1@Q} requires a value."
      fi
      shift 2
      ;;
    '--entrypoints-path')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      ENTRYPOINTS_PATH="$2"
      shift 2
      ;;
    '--generate-entrypoints')
      if [ -n "${2-}" ]; then
        csv_read '_ENTRYPOINTS_GENERATE' "$2"
        check_arg_filename_items "$1" "${_ENTRYPOINTS_GENERATE[@]}"
      elif [ -z "${2-unset}" ]; then
        _ENTRYPOINTS_GENERATE=('/NOOP')
      else
        die "Argument ${1@Q} requires a value."
      fi
      shift 2
      ;;
    '--modules-path')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      MODULES_PATH="$2"
      shift 2
      ;;
    '--no-verify-import')
      _VERIFY_IMPORT=''
      shift
      ;;
    '--post-build-cmd')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      _POST_BUILD_CMD="$2"
      shift 2
      ;;
    '--post-entrypoint-generate-cmd')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      _POST_ENTRYPOINT_GENERATE_CMD="$2"
      shift 2
      ;;
    '--post-extraction-cmd')
      [ -n "${2-}" ] || die "Argument ${1@Q} requires a value."
      _POST_EXTRACTION_CMD="$2"
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

if [ -n "$_BUILD_ONLY" ]; then
  [ "${#_ENTRYPOINTS_EXPECTED[@]}" == '0' ] ||
    die '--build-only and --expect-entrypoints are not compatible.'
  [ "${#_ENTRYPOINTS_GENERATE[@]}" == '0' ] ||
    die '--build-only and --generate-entrypoints are not compatible.'
fi

if [ -z "$_VERIFY_IMPORT" ]; then
  [ -z "$_MODE_PYTEST" ] ||
    die '--no-verify-import and --pytest are not compatible.'
  [ -z "$_MODE_UNITTEST" ] ||
    die '--no-verify-import and --unittest are not compatible.'
fi

check_python

if [ "${#_ENTRYPOINTS_GENERATE[@]}" -ge '1' ]; then
  if [ "${_ENTRYPOINTS_GENERATE[0]}" == '/NOOP' ]; then
    _ENTRYPOINTS_GENERATE=()
  else
    check_arg_list_a_contains_all_b_list_items \
      --expect-entrypoints --generate-entrypoints \
      "${#_ENTRYPOINTS_EXPECTED[@]}" "${#_ENTRYPOINTS_GENERATE[@]}" \
      "${_ENTRYPOINTS_EXPECTED[@]}" "${_ENTRYPOINTS_GENERATE[@]}"
  fi
else
  _ENTRYPOINTS_GENERATE=("${_ENTRYPOINTS_EXPECTED[@]}")
fi

if [ "${#_FILES_EXTRACT[@]}" -ge '1' ]; then
  if [ "${_FILES_EXTRACT[0]}" == '/NOOP' ]; then
    _FILES_EXTRACT=()
  else
    check_arg_list_a_contains_all_b_list_items \
      --expect-files --extract-files \
      "${#_FILES_EXPECTED[@]}" "${#_FILES_EXTRACT[@]}" \
      "${_FILES_EXPECTED[@]}" "${_FILES_EXTRACT[@]}"
  fi
else
  _FILES_EXTRACT=("${_FILES_EXPECTED[@]}")
fi

if [ "${#_MODULES_EXTRACT[@]}" -ge '1' ]; then
  if [ "${_MODULES_EXTRACT[0]}" == '/NOOP' ]; then
    _MODULES_EXTRACT=()
  else
    check_arg_list_a_contains_all_b_list_items \
      --expect-modules --extract-modules \
      "${#_MODULES_EXPECTED[@]}" "${#_MODULES_EXTRACT[@]}" \
      "${_MODULES_EXPECTED[@]}" "${_MODULES_EXTRACT[@]}"
  fi
else
  _MODULES_EXTRACT=("${_MODULES_EXPECTED[@]}")
fi

if [ -n "$TARGET_DIR" ]; then
  if [ -n "$MODULES_PATH" ]; then
    check_arg_valid_path "$MODULES_PATH" 'Modules'
  else
    MODULES_PATH="${PREFIX#/}/lib/python$PYTHON_VERSION/site-packages"
  fi

  if [ -n "$ENTRYPOINTS_PATH" ]; then
    check_arg_valid_path "$ENTRYPOINTS_PATH" 'Entrypoints'
  else
    ENTRYPOINTS_PATH="${PREFIX#/}/bin"
  fi

  ENTRYPOINTS_TARGET_DIR="$TARGET_DIR/$ENTRYPOINTS_PATH"
  MODULES_TARGET_DIR="$TARGET_DIR/$MODULES_PATH"
  run mkdir -p -- "$ENTRYPOINTS_TARGET_DIR" "$MODULES_TARGET_DIR"
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

[ "${#_MODULES_EXPECTED[@]}" -ge '1' ] ||
  _MODULES_EXPECTED=("$WHEEL_NAME")

if [ -z "$_BUILD_ONLY" ]; then
  info 'Verifying contents of wheel...'
  wheel_verify_content

  info 'Parsing entrypoints in wheel...'
  wheel_entrypoints_parse

  if [ -n "$_VERIFY_IMPORT" ]; then
    info "Verifying that the wheel's modules are not already installed..."
    _installed=()
    for _module in "${_MODULES_EXPECTED[@]}"; do
      check_module_import "$_module"
      [ -n "$_MODULE_IMPORT_ERROR" ] || _installed+=("$_module")
    done
    [ "${#_installed[@]}" == '0' ] ||
      die "Found already installed modules in this python environment: \
${_installed[*]@Q}"

    hook_cmd_run 'pre-install' "$_POST_INSTALL_CMD"
    info 'Installing wheel...'
    wheel_install
    info 'Successfully installed wheel.'
    hook_cmd_run 'post-install' "$_POST_INSTALL_CMD"

    info "Verifying that the installed wheel's modules can be imported..."
    for _module in "${_MODULES_EXPECTED[@]}"; do
      check_module_import "$_module"
      [ -z "$_MODULE_IMPORT_ERROR" ] ||
        die "Failed to import module ${_module@Q}: $_MODULE_IMPORT_ERROR"
    done
    info "Successfully imported module(s): ${_MODULES_EXPECTED[*]@Q}"

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
    info 'Uninstalling wheel again...'
    wheel_uninstall
    info 'Successfully uninstalled wheel.'
    hook_cmd_run 'post-uninstall' "$_POST_UNINSTALL_CMD"
  fi
fi

if [ -n "$TARGET_DIR" ]; then
  info "Extracting files from wheel into ${MODULES_TARGET_DIR@Q}..."
  wheel_extract
  info 'Successfully extracted files from wheel.'
  hook_cmd_run 'post-extraction' "$_POST_EXTRACTION_CMD"

  if [ -z "$_BUILD_ONLY" ] && [ "${#_ENTRYPOINTS_GENERATE[@]}" -ge '1' ]; then
    info 'Generating entrypoints from wheel...'
    wheel_entrypoints_generate
    info "Successfully generated entrypoints."
    hook_cmd_run 'post-entrypoints-generate' "$_POST_ENTRYPOINT_GENERATE_CMD"
  fi
fi

if [ -n "$WHEEL_DIR" ]; then
  info "Copying wheel into ${WHEEL_DIR@Q}..."
  run cp -a -- "$WHEEL_FILE" "$WHEEL_DIR/"
  info 'Successfully copied wheel.'
fi

info 'All done.'
_EXPECTED_EXIT='yes'
