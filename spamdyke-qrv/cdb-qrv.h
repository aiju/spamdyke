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

#ifndef CDB_H
#define CDB_H

#ifdef HAVE_STDINT_H

#include <stdint.h>

#else /* HAVE_STDINT_H */
#ifdef HAVE_SYS_INTTYPES_H

#include <sys/inttypes.h>

#endif /* HAVE_SYS_INTTYPES_H */
#endif /* HAVE_STDINT_H */

#define CDB_INDEX_COUNT                 256
#define CDB_HASH_SEED                   5381
#define CDB_HASH_SIZE                   256

struct cdb_index
  {
  uint32_t offset;
  uint32_t num_slots;
  };

struct cdb_hash_slot
  {
  uint32_t hash_value;
  uint32_t offset;
  };

struct cdb_record_header
  {
  uint32_t key_length;
  uint32_t data_length;
  };

uint32_t letoh(uint32_t target_int);
uint32_t cdb_hash(char *target_key, int target_strlen);
int search_assign_cdb(struct qrv_settings *current_settings, char *destination, int size_destination, char *search_filename, char *target_address, int strlen_target_address, int *return_strlen_address);
int search_morercpthosts_cdb(struct qrv_settings *current_settings, char *search_filename, char *target_domain, int strlen_target_domain);

#endif /* CDB_H */
