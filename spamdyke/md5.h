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
#ifndef MD5_H
#define MD5_H

#ifdef HAVE_STDINT_H

#include <stdint.h>

#else /* HAVE_STDINT_H */
#ifdef HAVE_SYS_INTTYPES_H

#include <sys/inttypes.h>

#endif /* HAVE_SYS_INTTYPES_H */
#endif /* HAVE_STDINT_H */

#ifndef WITHOUT_CONFIG_TEST

#include "config.h"

unsigned char *md5(unsigned char destination[16], unsigned char *source, uint64_t source_len);

#endif /* WITHOUT_CONFIG_TEST */

#endif /* MD5_H */
