/*
  spamdyke -- a filter for stopping spam at connection time.
  Copyright (C) 2015 Sam Clippinger (samc (at) silence (dot) org)

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License version 2 as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "config-qrv.h"
#include <stdio.h>
#include "spamdyke-qrv.h"
#include "usage-qrv.h"

void usage(int header_only)
  {
  fprintf(stderr,
    USAGE_MESSAGE_HEADER
    );

  if (header_only)
    fprintf(stderr,
      "Use -h for an option summary or see README.html for complete documentation.\n"
      "\n"
      );
  else
    fprintf(stderr,
      "USAGE: spamdyke-qrv [ FLAGS ] DOMAIN USERNAME\n"
      "\n"
      "spamdyke-qrv is an external utility for spamdyke to perform qmail recipient\n"
      "validation.  spamdyke-qrv is intended to run as an external process with root\n"
      "permissions and can be started by spamdyke when recipient validation is\n"
      "needed on a qmail server.\n"
      "\n"
      "spamdyke-qrv assumes the address has a domain name and the domain name is listed\n"
      "in either qmail's \"rcpthosts\" file or qmail's \"morercpthosts\" CDB file or\n"
      "relaying is permitted for some other reason (e.g. RELAYCLIENT is set).  In other\n"
      "words, spamdyke-qrv begins its validation at step 7 in the flowchart found in\n"
      "the \"documentation\" folder.  Steps 1, 2, 5 and 6 are assumed to have been\n"
      "performed by spamdyke before spamdyke-qrv was started.\n"
      "\n"
      "DOMAIN and USERNAME are required.  If the environment variable RELAYCLIENT is\n"
      "set, its contents should NOT be appended to the domain name before spamdyke-qrv\n"
      "is started.\n"
      "\n"
      "The results of the validation are indicated through spamdyke-qrv's exit code:\n"
      "  " STRINGIFY(DECISION_UNKNOWN) ": No determination was made\n"
      "  " STRINGIFY(DECISION_VALID) ": The address is valid\n"
      "  " STRINGIFY(DECISION_INVALID) ": The address is invalid (delivery is not possible)\n"
      "  " STRINGIFY(DECISION_UNAVAILABLE) ": The address is unavailable (messages will be queued by qmail)\n"
      "\n"

#ifdef WITH_VPOPMAIL_SUPPORT

      "This version of spamdyke-qrv was compiled with the following full paths to\n"
      "vpopmail's utilities, which will be run if a vpopmail-controlled address is\n"
      "being validated:\n"
      "\tvalias: " VPOPMAIL_VALIAS_PATH "\n"
      "\tvuserinfo: " VPOPMAIL_VUSERINFO_PATH "\n"
      "\n"

#endif /* WITH_VPOPMAIL_SUPPORT */

      "Available flags:\n"
      "\n"
      "-h\n"
      "  Displays this help screen.\n"
      "\n"

#ifdef WITH_EXCESSIVE_OUTPUT

      "-v\n"
      "  Produce verbose output.  This flag can be given a second time for excessively\n"
      "  detailed output.\n"
      "\n"
      "-d\n"
      "  Print a diagnostic message to show the path followed through the flowchart.\n"
      "  Really only useful from a test script.\n"

#else /* WITH_EXCESSIVE_OUTPUT */

      "-v\n"
      "  Produce verbose output.  This version of spamdyke-qrv was compiled without\n"
      "  excessive output, so using this flag multiple times has no additional effect.\n"
      "\n"
      "-d\n"
      "  This version of spamdyke-qrv was compiled without excessive output, so this\n"
      "  option has no effect.\n"

#endif /* WITH_EXCESSIVE_OUTPUT */

      "\n"
      "--qmail-assign-cdb CDB\n"
      "  Use CDB as qmail's \"assign\" CDB file instead of the default file path.\n"
      "  Default: " DEFAULT_QMAIL_ASSIGN_CDB "\n"
      "\n"
      "--qmail-defaultdelivery-file FILE\n"
      "  Use FILE as qmail's \"defaultdelivery\" file instead of the default file path.\n"
      "  Default: " DEFAULT_QMAIL_DEFAULTDELIVERY_FILE "\n"
      "\n"
      "--qmail-envnoathost-file FILE\n"
      "  Use FILE as qmail's \"envnoathost\" file instead of the default file path.\n"
      "  Default: " DEFAULT_QMAIL_ENVNOATHOST_FILE "\n"
      "\n"
      "--qmail-locals-file FILE\n"
      "  Use FILE as qmail's \"locals\" file instead of the default file path.\n"
      "  Default: " DEFAULT_QMAIL_LOCALS_FILE "\n"
      "\n"
      "--qmail-me-file FILE\n"
      "  Use FILE as qmail's \"me\" file instead of the default file path.\n"
      "  Default: " DEFAULT_QMAIL_ME_FILE "\n"
      "\n"
      "--qmail-morercpthosts-cdb CDB\n"
      "  Use CDB as qmail's \"morercpthosts.cdb\" CDB file instead of the default file path.\n"
      "  Default: " DEFAULT_QMAIL_MORERCPTHOSTS_CDB "\n"
      "\n"
      "--qmail-percenthack-file FILE\n"
      "  Use FILE as qmail's \"percenthack\" file instead of the default file path.\n"
      "  Default: " DEFAULT_QMAIL_PERCENTHACK_FILE "\n"
      "\n"
      "--qmail-rcpthosts-file FILE\n"
      "  Use FILE as qmail's \"rcpthosts\" file instead of the default file path.\n"
      "  Default: " DEFAULT_QMAIL_RCPTHOSTS_FILE "\n"
      "\n"
    );

  return;
  }
