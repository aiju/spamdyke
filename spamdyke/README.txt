This directory contains the main spamdyke program.

QmailToaster users: Don't install spamdyke from source, use the install script
in QmailToaster Plus instead:
  http://qtp.qmailtoaster.com/

================================================================================
=== TL;DR INSTRUCTIONS FOR EVERYONE ELSE
================================================================================

Detect dependencies and libraries:
  ./configure

Compile:
  make

Install:
  make install

Create a configuration file for spamdyke:
  cp ../documentation/spamdyke.conf.basic /etc/spamdyke.conf

Edit the script that starts qmail -- its name depends on how qmail was setup:
For Plesk users: /etc/xinetd.d/smtp_psa
For Debian users: /etc/init.d/qmail
Others: /service/qmail-smtpd/run
Insert the spamdyke command before the qmail-smtpd command:
  ... /usr/local/bin/spamdyke -f /etc/spamdyke.conf /var/qmail/bin/qmail-smtpd ...

Restart qmail -- the exact command depends on how qmail was setup:
For Plesk users: killall -SIGHUP xinetd
For Debian users: /etc/init.d/qmail restart
Others: qmailctl restart

That's it!  Lots more spamdyke options are available, read about them and enable
them in your configuration file.

================================================================================

Full documentation can be found in the "documentation" directory.
