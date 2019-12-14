This directory contains the spamdyke-qrv program, which is a helper program for
spamdyke to use when recipient validation is needed on a qmail server.  If
spamdyke's recipient validation isn't needed (e.g. Plesk servers) or this isn't
a qmail server, there's no need to even compile this program.

spamdyke-qrv only performs recipient validation and must be run as root in order
to have access to all the files needed to correctly validate an address.  This
usually means the resulting binary must be setuid root.

QmailToaster users: Don't install spamdyke from source, use the install script
in QmailToaster Plus instead:
  http://qtp.qmailtoaster.com/

Plesk users: Don't install spamdyke-qrv at all, Plesk already performs recipient
validation; spamdyke doesn't need to do it.

================================================================================
=== TL;DR INSTRUCTIONS FOR EVERYONE ELSE
================================================================================

Detect dependencies and libraries:
  ./configure
OR if vpopmail is in use:
  ./configure --with-vpopmail-support VALIAS_PATH=/path/to/valias VUSERINFO_PATH=/path/to/vuserinfo

Compile:
  make

Install (as root):
  make install

READ THE CONFIGURATION INSTRUCTIONS IN THE "documentation" DIRECTORY!

================================================================================

Full documentation can be found in the "documentation" directory.
