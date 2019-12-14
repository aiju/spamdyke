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
#ifndef TLS_H

#ifndef HAVE_LIBSSL

#define NETWORK_CAN_READ(A)             0
#define NETWORK_READ(A,B,C,D)           read(B,C,D)
#define NETWORK_WRITE(A,B,C,D)          write(B,C,D)

#else /* HAVE_LIBSSL */

#include "spamdyke.h"

#define NETWORK_CAN_READ(A)             tls_can_read(A)
#define NETWORK_READ(A,B,C,D)           tls_read(A,B,C,D)
#define NETWORK_WRITE(A,B,C,D)          tls_write(A,B,C,D)

int tls_can_read(struct filter_settings *current_settings);
ssize_t tls_read(struct filter_settings *current_settings, int target_fd, void *target_buf, size_t num_bytes);
ssize_t tls_write(struct filter_settings *current_settings, int target_fd, void *target_buf, size_t num_bytes);
int tls_init(struct filter_settings *current_settings);
int tls_start(struct filter_settings *current_settings, int read_fd, int write_fd);
int tls_end(struct filter_settings *current_settings, int read_fd);
int tls_test(struct filter_settings *current_settings);

#endif /* HAVE_LIBSSL */

char *tls_state_desc(struct filter_settings *current_settings);

#endif /* TLS_H */
