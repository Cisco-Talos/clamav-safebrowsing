# clamav-safebrowsing

## About

clamav-safebrowsing (`clamsb`) is a project that acquires the Google
Safebrowsing Lists through the Google Safebrowsing V4 API
(https://safebrowsing.google.com/) and packages the data into a ClamAV GDB
(Google Database) signature file, supporting Python 2.7 and Python 3.x.

`clamsb` handles full and update syncing with the Safebrowsing API, reducing the
expense of retrieving list updates after the first retrieval. Additionally,
`clamsb` provides methods to validate the existing database (provided that the
lists are up-to-date), dump/load a pickled copy of the Safebrowsing API update
object, and purge all existing records.

`clamsb` is comprised of two entrypoint applications to manage the safebrowsing
lists within the database and generate GDB signature files and various modules
for interacting with the database and Safebrowsing API.

## Installation

`clamsb` requires a few third-party libraries that are listed in the
requirements.txt file; these libraries can also be installed through `setup.py`.

`clamsb` requires a Google API key with access to the Safebrowsing V4 API.
Instructions for acquiring an API key can be found at https://developers.google.com/safe-browsing/v4/get-started.

`clamsb` requires a MySQL database to manage Safebrowsing Lists and build logs.
The database will need a user with credentials to create, modify, and delete
tables on the database. It is recommended you generate a specialized database
and user for access. Once the database parameters are specified to the `clamsb`
configuration, required tables will automatically be generated on the first
sync.

`clamsb` can be installed from this directory using the `setup.py` script but
can be ran directly from this directory. `clamsbsync.py` and `clamsbwrite.py`
are exposed as entrypoint applications if installed.

## Usage

`clamsbsync.py` is the primary entrypoint application handling all database
management and safebrowsing api access operations.

`clamsbsync.py` supports the following commands:

- `build`/`b`(*)
  - Performs a sync with the safebrowsing API and then invokes `clamsbwrite.py`
    to output a `safebrowsing.gdb` to the output directory.

- `sync`/`s`
  - Perform a sync (no output generated).

- `validate`/`v`
  - Determine if the current lists stored in the database are up-to-date and
    valid (does not perform syncing).

- `dump`/`d`
  - Dump the updates object retrieved from the safebrowsing API to a pickled
    file (updates.p).

- `load`/`l`
  - Load an updates object from a pickled file (updates.p).

- `purge`
  - Drop all database hashes and prefixes (does not include build summaries).

By default, `clamsbsync.py` runs the `build` command if no command is specified.

`clamsbwrite.py` is a secondary application that reads from the database and
generates a ClamAV GDB signature file. It does not perform any Safebrowsing API
calls and only records build summaries in the database. If ran without
performing a sync, it will generate an empty file.

Both `clamsbsync.py` and `clamsbwrite.py` require a configuration file written
in the Apache Configuration Format that detail the connection specifications
for accessing the MySQL database and Google Safebrowsing API. An example
configuration file can be found in `./etc/safebrowsing.conf.example`.

Both `clamsbsync.py` and `clamsbwrite.py` have the following options:

- `-C`, `--config`
  - Used to override the default config path (`/etc/clamav/safebrowsing.conf`).

- `-d`, `--debug`
  - Set the logger logging levels to `logging.DEBUG`.

- `-v`, `--verbose`
  - Set the logger logging levels to `logging.INFO`.

- `--logfile`
  - Used to specify a logfile to use with the python logging module.

- `-h`, `--help`
  - Print out a help message.

## License & Copyright

Copyright (C) 2020 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
