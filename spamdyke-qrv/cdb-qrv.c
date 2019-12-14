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
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include "spamdyke-qrv.h"
#include "cdb-qrv.h"
#include "log-qrv.h"

/*
 * These routines search CDB files for records.  CDB files are binary "constant
 * database" files, a format created by Daniel J. Bernstein and rather
 * laughably documented at:
 *   http://cr.yp.to/cdb.html
 */

/*
 * Converts an integer from little-endian (least significant byte first) to the
 * native format.
 *
 * RETURN VALUE:
 *   integer in native format
 */
uint32_t letoh(uint32_t target_int)
  {
  static int little_endian = -1;
  uint32_t return_value;
  int i;
  union
    {
    uint32_t integer;
    unsigned char string[4];
    } convert;

  if (little_endian == -1)
    {
    convert.string[0] = 0x01;
    convert.string[1] = 0x00;
    convert.string[2] = 0x00;
    convert.string[3] = 0x00;
    little_endian = (convert.integer == 1) ? 1 : 0;
    }

  if (!little_endian)
    {
    for (i = 0; i < 4; i++)
      convert.string[i] = (unsigned char)((target_int >> (i * 8)) & 0xFF);

    return_value = convert.integer;
    }
  else
    return_value = target_int;

  return(return_value);
  }

/*
 * RETURN VALUE:
 *   CDB hash from target_key
 */
uint32_t cdb_hash(char *target_key, int target_strlen)
  {
  uint32_t return_value;
  int i;

  return_value = CDB_HASH_SEED;
  if (target_key != NULL)
    for (i = 0; i < target_strlen; i++)
      return_value = ((return_value << 5) + return_value) ^ target_key[i];

  return(return_value);
  }

/*
 * RETURNS:
 *   -2 = error
 *   -1 = not found
 *   length of data written to destination = found
 */
int find_cdb_record(struct qrv_settings *current_settings, char *destination, int size_destination, char *search_filename, char *target_key, int target_strlen, FILE *target_cdb, struct cdb_index *target_indexes)
  {
  int return_value;
  uint32_t hash;
  int hash_index;
  uint32_t hash_table_offset;
  uint32_t hash_table_length;
  uint32_t slot_num;
  uint32_t start_slot_num;
  struct cdb_hash_slot tmp_slot;
  uint32_t tmp_hash;
  uint32_t tmp_offset;
  uint32_t tmp_key_length;
  uint32_t tmp_data_length;
  struct cdb_record_header tmp_record_header;
  char tmp_key[MAX_BUF + 1];

  return_value = -1;

  if ((target_key != NULL) &&
      (target_cdb != NULL) &&
      (target_indexes != NULL) &&
      (((destination == NULL) &&
        (size_destination == 0)) ||
       ((destination != NULL) &&
        (size_destination > 0))))
    {
    /*
     * Calculate the hash from the key, then use it to find the position of the
     * entry in the main index.  The index entry will contain the offset of the
     * hashed entry and the number of "slots" under that hash value.  The
     * initial slot number is calculated from the hash.
     */
    hash = cdb_hash(target_key, target_strlen);
    hash_index = hash % CDB_HASH_SIZE;
    hash_table_offset = letoh(target_indexes[hash_index].offset);
    hash_table_length = letoh(target_indexes[hash_index].num_slots);
    slot_num = (hash_table_length > 0) ? ((hash / CDB_HASH_SIZE) % hash_table_length) : 0;
    start_slot_num = slot_num;

    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_CDB_SEARCH, search_filename, target_strlen, target_strlen, target_key, hash, hash_index, hash_table_length, slot_num);

    if (hash_table_length > 0)
      {
      do
        {
        QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_CDB_HASH, hash, hash_index, hash_table_offset, hash_table_length, slot_num);

        if (fseek(target_cdb, hash_table_offset + (slot_num * sizeof(struct cdb_hash_slot)), SEEK_SET) == 0)
          {
          /*
           * Seek to the position of the "slot" within the hash entry and read it
           * to find the hash of the record stored there and the offset of the
           * record header.
           */
          if (fread(&tmp_slot, sizeof(struct cdb_hash_slot), 1, target_cdb) == 1)
            {
            tmp_hash = letoh(tmp_slot.hash_value);
            tmp_offset = letoh(tmp_slot.offset);

            QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_CDB_SLOT, tmp_hash, tmp_offset);

            /*
             * If the hash doesn't match, it's a collision and the slot number
             * should be incremented.  If the offset value is 0, the "slot" is
             * empty and the slot number should be incremented.
             */
            if ((tmp_hash == hash) &&
                (tmp_offset > 0))
              {
              if (fseek(target_cdb, tmp_offset, SEEK_SET) == 0)
                {
                /*
                 * Seek to the record header position and read it to find the
                 * actual key and the offset of the data.  If the key does not
                 * match, it is a hash collision and the slot number should be
                 * incremented until a matching key is found or until there are
                 * no more slots.
                 */
                if (fread(&tmp_record_header, sizeof(struct cdb_record_header), 1, target_cdb) == 1)
                  {
                  tmp_key_length = letoh(tmp_record_header.key_length);
                  tmp_data_length = letoh(tmp_record_header.data_length);

                  QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_CDB_RECORD, tmp_key_length, tmp_data_length);

                  if ((tmp_key_length == 0) ||
                      (fread(tmp_key, MINVAL(tmp_key_length, MAX_BUF), 1, target_cdb) == 1))
                    {
                    QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_CDB_KEY, MINVAL(tmp_key_length, MAX_BUF), MINVAL(tmp_key_length, MAX_BUF), tmp_key);

                    if ((tmp_key_length == target_strlen) &&
                        (strncmp(target_key, tmp_key, target_strlen) == 0))
                      {
                      if (return_value != -2)
                        {
                        if ((tmp_data_length == 0) ||
                            (destination == NULL) ||
                            (fread(destination, MINVAL(size_destination, tmp_data_length), 1, target_cdb) == 1))
                          {
                          if (destination != NULL)
                            {
                            return_value = MINVAL(size_destination, tmp_data_length);
                            destination[return_value] = '\0';

                            QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_CDB_DATA, return_value, escape_log_text(destination, return_value));
                            }
                          else
                            {
                            QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_CDB_DATA_NULL, tmp_data_length);
                            return_value = tmp_data_length;
                            }
                          }
                        else
                          {
                          if (feof(target_cdb))
                            QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_EOF, search_filename);
                          else
                            QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_READ "%s", search_filename, strerror(errno));

                          return_value = -2;
                          }
                        }

                      break;
                      }
                    else
                      {
                      slot_num++;
                      if (slot_num == hash_table_length)
                        slot_num = 0;
                      }
                    }
                  else
                    {
                    if (feof(target_cdb))
                      QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_EOF, search_filename);
                    else
                      QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_READ "%s", search_filename, strerror(errno));

                    return_value = -2;
                    }
                  }
                else
                  {
                  if (feof(target_cdb))
                    QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_EOF, search_filename);
                  else
                    QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_READ "%s", search_filename, strerror(errno));

                  return_value = -2;
                  }
                }
              else
                {
                QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_SEEK "%s", tmp_offset, search_filename, strerror(errno));
                return_value = -2;
                }
              }
            else
              {
              slot_num++;
              if (slot_num == hash_table_length)
                slot_num = 0;
              }
            }
          else
            {
            if (feof(target_cdb))
              QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_EOF, search_filename);
            else
              QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_READ "%s", search_filename, strerror(errno));

            return_value = -2;
            }
          }
        else
          {
          QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_SEEK "%s", hash_table_offset + (slot_num * sizeof(struct cdb_hash_slot)), search_filename, strerror(errno));
          return_value = -2;
          }
        }
      while ((return_value != -2) &&
           (slot_num != start_slot_num));
      }
    }

  return(return_value);
  }

/*
 * If an exact match is found, return_strlen_address will be set to -1.  Otherwise it will be set to the length of the key that was finally found (implies a wildcard was matched).
 *
 * Return value:
 *   ERROR: -2
 *   NOT FOUND: -1
 *   FOUND: number of bytes written to destination
 */
int search_assign_cdb(struct qrv_settings *current_settings, char *destination, int size_destination, char *search_filename, char *target_address, int strlen_target_address, int *return_strlen_address)
  {
  int return_value;
  int i;
  FILE *tmp_file;
  struct cdb_index indexes[CDB_INDEX_COUNT];
  char tmp_key[MAX_BUF + 1];
  int strlen_key;
  char tmp_destination[MAX_BUF + 1];
  int strlen_destination;
  char tmp_wildcards[MAX_BUF + 1];
  int strlen_wildcards;

  return_value = -1;

  if ((target_address != NULL) &&
      (search_filename != NULL) &&
      (destination != NULL) &&
      (size_destination > 0))
    {
    if ((tmp_file = fopen(search_filename, "r")) != NULL)
      {
      if (fread(indexes, sizeof(struct cdb_index), CDB_INDEX_COUNT, tmp_file) == CDB_INDEX_COUNT)
        {
        strlen_key = SNPRINTF(tmp_key, MAX_BUF, "%c%.*s%c", QMAIL_ASSIGN_PREFIX, strlen_target_address, target_address, '\0');
        if (((return_value = find_cdb_record(current_settings, destination, size_destination, search_filename, tmp_key, strlen_key, tmp_file, indexes)) > 0) &&
            (return_strlen_address != NULL))
          *return_strlen_address = -1;

        strlen_wildcards = -1;
        while ((return_value == -1) &&
               (strlen_key > 1))
          {
          strlen_key--;
          if ((strlen_destination = find_cdb_record(current_settings, tmp_destination, MAX_BUF, search_filename, tmp_key, strlen_key, tmp_file, indexes)) > 0)
            {
            if (strlen_wildcards == -1)
              {
              if ((strlen_wildcards = find_cdb_record(current_settings, tmp_wildcards, MAX_BUF, search_filename, "", 0, tmp_file, indexes)) <= 0)
                {
                QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_WILDCARD, search_filename);
                break;
                }
              }

            for (i = 0; i < strlen_wildcards; i++)
              {
              QRV_LOG_EXCESSIVE(current_settings, LOG_EXCESSIVE_VALIDATE_WILDCARD_SEARCH, tmp_wildcards[i], strlen_key - 1, tmp_key[strlen_key - 1]);

              if (tmp_key[strlen_key - 1] == tmp_wildcards[i])
                {
                return_value = MINVAL(strlen_destination, size_destination);
                memcpy(destination, tmp_destination, return_value);

                if (return_strlen_address != NULL)
                  *return_strlen_address = strlen_key - 1;

                break;
                }
              }
            }
          }
        }
      else
        {
        if (feof(tmp_file))
          QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_EOF, search_filename);
        else
          QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_READ "%s", search_filename, strerror(errno));

        return_value = -2;
        }

      fclose(tmp_file);
      }
    else
      {
      QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_OPEN "%s", search_filename, strerror(errno));
      return_value = -2;
      }
    }

  return(return_value);
  }

/*
 * Return value:
 *   ERROR: -2
 *   NOT FOUND: -1
 *   FOUND: number of bytes in domain name
 */
int search_morercpthosts_cdb(struct qrv_settings *current_settings, char *search_filename, char *target_domain, int strlen_target_domain)
  {
  int return_value;
  FILE *tmp_file;
  struct cdb_index indexes[CDB_INDEX_COUNT];
  char tmp_key[MAX_BUF + 1];
  int tmp_strlen;

  return_value = -1;

  if (target_domain != NULL)
    {
    if ((tmp_file = fopen(search_filename, "r")) != NULL)
      {
      if (fread(indexes, sizeof(struct cdb_index), CDB_INDEX_COUNT, tmp_file) == CDB_INDEX_COUNT)
        {
        tmp_strlen = SNPRINTF(tmp_key, MAX_BUF, "%.*s", strlen_target_domain, target_domain);
        return_value = find_cdb_record(current_settings, NULL, 0, search_filename, tmp_key, tmp_strlen, tmp_file, indexes);
        }
      else
        {
        if (feof(tmp_file))
          QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_EOF, search_filename);
        else
          QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_READ "%s", search_filename, strerror(errno));

        return_value = -2;
        }

      fclose(tmp_file);
      }
    else
      {
      QRV_LOG_ERROR(current_settings, LOG_ERROR_CDB_OPEN "%s", search_filename, strerror(errno));
      return_value = -2;
      }
    }

  return(return_value);
  }
