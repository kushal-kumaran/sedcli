# sedcli and libsed overview

TCG Opal is an industry standard allowing Self-Encrypting Drives management, i.e. enable locking, configuring users, locking ranges etc.

Sedcli is an utility for managing NVMe SEDs that are TCG Opal complaint.

Libsed is a library allowing to programatically manage NVMe SEDs that are TCG Opal complaint.

## Getting started

In order to get started use following steps (\<sedcli\> denotes top level directory for sedcli):

```
# navigate to source directory
cd <sedcli>/src

# perform build environment configuration and run compilation
chmod +x ./configure
./configure
make all
make install
make install-cert

# invoke sedcli help to available commands and its syntax
sedcli --help

```
For more information goto [doc](doc) directory.

## Features

* Interactive management of NVMe SED allowing to: configure locking, change lock state, revert disk back to manafactured state
* Auto management with disk key being retrieved from network attached Key Management Server that is OASIS KMIP complaint

## Talks and papers

* SNIA SDC 2019: [Data at Rest Protection at Scale with NVMe and Opal](https://www.youtube.com/watch?v=5mmJlNplcAY)

## Contributing

We encourage contributions! Patches are accepted via pull request:
* Contributions into sedcli are accepted on GPL-2.0-or-later license
* Contributions into libsed are accepted on LGPL-2.1-or-later license

## Maintainers

* Piotr Rudnicki <piotr.rudnicki@solidigm.com>

Feel free to contact us anytime with questions, feedback or suggestions.
We would love to hear how you see sedcli going forward.
