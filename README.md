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

## Requirements

`clamsb` requires:

- A **lot** of RAM. We recommend a system with at least 12GB of RAM.

- A few third-party libraries that are listed in the
requirements.txt file; these libraries can also be installed through `setup.py`.

- A Google API key with access to the Safebrowsing V4 API.
Instructions for acquiring an API key can be found at https://developers.google.com/safe-browsing/v4/get-started.

- A MySQL database to manage Safebrowsing Lists and build logs.
The database will need a user with credentials to create, modify, and delete
tables on the database. It is recommended you generate a specialized database
and user for access. Once the database parameters are specified to the `clamsb`
configuration, required tables will automatically be generated on the first
sync.

## Setup

`clamsb` can be installed from this directory using the `setup.py` script but
can also be run directly from this directory. `clamsbsync.py` and `clamsbwrite.py`
are exposed as entrypoint applications if installed.

### Install and set up MySQL

The following will help you get started with setting up MySQL for `clamsb`.
Note that these instructions are for Ubuntu 20.04 and you may need to do 
something slightly different for your system.

First, install MySQL if not already present:
```bash
sudo apt update
sudo apt install -y mysql-server libmysqlclient-dev
```

Then enter the MySQL monitor to add a user, a database, and set permissions:
```bash
sudo mysql
```

The following will create your SQL user account, create the required database,
and grant the required permissions. 

> *Important*: Select your own password to replace "PASSWORDHERE".

```sql
CREATE USER 'sbclient'@'localhost' IDENTIFIED BY 'PASSWORDHERE';
GRANT CREATE, ALTER, DROP, INSERT, UPDATE, DELETE, SELECT, REFERENCES, RELOAD on *.* TO 'sbclient'@'localhost' WITH GRANT OPTION;
CREATE DATABASE sbclient;
exit
```

You can find additional help with creating users and granting permissions in
[DigitalOcean's community tutorials](https://www.digitalocean.com/community/tutorials/how-to-create-a-new-user-and-grant-permissions-in-mysql).

### Obtain a Google Safebrowsing API key

Login to the [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
with a Google account that you're able to use for this purpose. 

On the top right, click "Create Project". 
Choose a memorable name for use with the Google Safebrowsing API.

Then, on the project page for your new project:
1. Click "Create Credentials" and select "API key".
2. Save this key somewhere safe. You will also need to place it in the `clamsb`
   config file, later.

After your key is created, you should also restrict where the key can be used.
In the "Actions" column, select "Edit key". 
1. Rename it to something memorable.
2. Select "Restrict key" and then select "Safe Browsing API"
3. Click "Save".

### Install the `clamav-safebrowsing` Python package

To install, run:
```bash
# Use git to get the clamav-safebrowsing code, or else download a zip or tarball and extract it.
git clone https://github.com/Cisco-Talos/clamav-safebrowsing.git

cd clamav-safebrowsing

# Activate a virtual environment so your Python packages aren't installed globally
python3 -m venv venv
source venv/bin/activate

# Install clamav-safebrowsing and its dependencies in the virtual environment.
python3 -m pip install . 
```

> *Tip*: Pip may fail to install if you did not already install the the MySQL
> server and client packages. 

> *Important*: Later, when you use `clamsbsync`, you may need to re-activate
> the virtual environment if running from a different terminal.
> You can also choose to skip the `venv` stuff, and use `sudo` to install
> the Python packages globally, like this:
> ```bash
> sudo python3 -m pip install .
> ```
> But know that version requirement conflicts can occur between different
> applications, and that installing Python packages globally with `pip` may
> also conflict with Python packages installed by an OS package manager.

### Create a `clamsb` config file

With your favorite text editor, create a new config file. The default config
path is `/etc/clamav/safebrowsing.conf`, but you can put it somewhere else
and pass the `--config` option when running `clamsbsync.py`.

```bash
sudo vim /etc/clamav/safebrowsing.conf
```

Fill in the following config details with the Safe Browsing API key
created earlier, and with the MySQL username and password selected
earlier:
```xml
<safebrowsing>
    # Google's apikey for the safebrowsing datafeed
    apikey = APIKEYHERE

    ## MySQL database parameters
    db_host = localhost
    db_user = sbclient
    db_pw = PASSWORDHERE
    db_name = sbclient

    ## outputdir is where the update Python makes its safebrowsing.gdb
    outputdir = /tmp/
</safebrowsing>
```

In the config above, the `outputdir` is set to `/tmp`, for simplicity.
You may wish to choose a better location. Just make sure the directory
exists and that the user that runs `clamsb` can create files there.

## Usage

`clamsbsync.py` is the primary entrypoint application handling all database
management and safebrowsing api access operations.

To download the get safebrowsing content and generate a new safebrowsing.gdb
database, simply run:
```bash
# Activate the virtual environment again, if in a new terminal
source venv/bin/activate

# Build safebrowsing.gdb
sudo ./venv/bin/python ./clamsbsync.py build
```

> *Note*: `sudo` is most likely required for `clamsbsync` to open the socket to
> communicate with `mysqld`. If you run everything as root, then you don't need
> to worry about using `venv` and can simply run:
> ```bash
> clamsbsync.py build
> ```

The sync and build process can take quite a while and will use a LOT of RAM.
Please be patient.

When complete, `safebrowsing.gdb` will be written to the output directory. 
*There is no need to manually run `clamsbwrite`.*

> *Known Issues*: If you encounter any issues, please see https://github.com/Cisco-Talos/clamav-safebrowsing/issues/9
> Some known issues include the following...
> 
> 1. You may see the following message:
>    ```
>    UpdateClient: WARNING: prefix set does not fully match retrieved list: expected 500 =/= retrieved 499
>    ```
>    It is safe to ignore this. For details, see https://github.com/Cisco-Talos/clamav-safebrowsing/issues/1
> 
> 2. After some sucecssful builds, you may encounter a failure due to a 
>    duplicate entry. The error will be something like this:
>    ```
>    MySQLdb._exceptions.IntegrityError: (1062, "Duplicate entry '000002ca-2' for key 'sbclient_v4_prefixes.PRIMARY'")
>    ```
>    There no fix at this time. The best option is to run `clamsbsync.py purge`
>    and then `clamsbsync.py build` again.
>    For details, see https://github.com/Cisco-Talos/clamav-safebrowsing/issues/9

### Additional Features

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
configuration file can be found in `./etc/safebrowsing.conf.sample`.

Both `clamsbsync.py` and `clamsbwrite.py` have the following options:

- `-C`, `--config`
  - Used to override the default config path (`/etc/clamav/safebrowsing.conf`).

- `-d`, `--debug`
  - Set the logger logging levels to `logging.DEBUG`.

- `-v`, `--verbose`
  - Set the logger logging levels to `logging.INFO`.

- `--logfile`
  - Used to specify a logfile to use with the Python logging module.

- `-h`, `--help`
  - Print out a help message.

## License & Copyright

Copyright (C) 2021 Cisco Systems, Inc. and/or its affiliates. All rights reserved.

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
