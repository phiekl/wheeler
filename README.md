<!--
SPDX-FileCopyrightText: 2024 Philip Eklöf

SPDX-License-Identifier: MIT
-->

# Wheeler

This tool uses python3 and pip to build a wheel of a local python project. The
wheel build is performed without isolation (i.e. all build dependencies must
already be installed in the system), and the index is disabled (no outgoing
requests to PyPi). Once installed, the wheel is installed into the user install
directory, verified that it can be imported, optionally tested using
pytest/unittest, and then uninstalled again.

The wheel may also be requested to be copied/extracted into a chosen directory.

Primarily meant to be used in a clean CI environment prior to distro packaging.

## Dependencies

- Tested using bash 5.2, should work with 5.0, might work with 4.x.
- `cp`, `mkdir`, `mktemp` (coreutils)
- `python3` in the configured prefix (see help text).

## Installation and usage

Simply add the script to your CI environment. Perhaps make it available as
`wheeler` in the PATH.

Have a look at the script's --help text for more information.
