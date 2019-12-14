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
#include <string.h>
#include "spamdyke.h"
#include "base64.h"

/*
 * These algorithms are described in RFC 2045.
 */

/*
 * Expects:
 *   destination == a preallocated buffer
 *   size_destination == the max size of destination
 *
 * Return value:
 *   length of the data added to destination, not counting null termination
 */
int base64_encode(unsigned char *destination, int size_destination, unsigned char *source, int strlen_source)
  {
  int return_value;
  int i;
  int j;
  char *alphabet = ALPHABET_BASE64;
  int dest_index[4];

  return_value = 0;
  i = 0;
  while ((i < strlen_source) &&
         (return_value < size_destination))
    {
    for (j = 0; j < 4; j++)
      dest_index[j] = -1;

    if (i < strlen_source)
      {
      dest_index[0] = (source[i] & 0xFC) >> 2;
      dest_index[1] = (source[i] & 0x03) << 4;
      }
    if ((i + 1) < strlen_source)
      {
      dest_index[1] |= (source[i + 1] & 0xF0) >> 4;
      dest_index[2] = (source[i + 1] & 0x0F) << 2;
      }
    if ((i + 2) < strlen_source)
      {
      dest_index[2] |= (source[i + 2] & 0xC0) >> 6;
      dest_index[3] = source[i + 2] & 0x3F;
      }

    for (j = 0; j < 4; j++)
      if (return_value < size_destination)
        destination[return_value++] = (dest_index[j] != -1) ? alphabet[dest_index[j]] : PAD_BASE64;

    i += 3;
    }

  if (return_value < size_destination)
    destination[return_value] = '\0';

  return(return_value);
  }

/*
 * Expects:
 *   destination == a preallocated buffer
 *   size_destination == the max size of destination
 *
 * Return value:
 *   length of the data added to destination, not counting null termination
 */
int base64_decode(unsigned char *destination, int size_destination, unsigned char *source, int strlen_source)
  {
  int return_value;
  int i;
  int j;
  char *alphabet = ALPHABET_BASE64;
  char *tmp_match;
  int source_index[4];

  return_value = 0;
  i = 0;
  while ((i < strlen_source) &&
         (return_value < size_destination))
    {
    for (j = 0; j < 4; j++)
      source_index[j] = -1;

    j = 0;
    while ((j < 4) &&
           ((i + j) < strlen_source))
      /* If necessary, this could be made faster with an ASCII->index lookup table instead of using strchr(). */
      if ((tmp_match = strchr(alphabet, source[i + j])) != NULL)
        {
        source_index[j] = tmp_match - alphabet;
        j++;
        }
      else
        i++;

    if ((return_value < size_destination) &&
        (source_index[0] != -1))
      destination[return_value++] = ((source_index[0] & 0x3F) << 2) | ((source_index[1] != -1) ? ((source_index[1] & 0x30) >> 4) : 0);
    if ((return_value < size_destination) &&
        (source_index[1] != -1))
      destination[return_value++] = ((source_index[1] & 0x0F) << 4) | ((source_index[2] != -1) ? ((source_index[2] & 0x3C) >> 2) : 0);
    if ((return_value < size_destination) &&
        (source_index[2] != -1))
      destination[return_value++] = ((source_index[2] & 0x03) << 6) | ((source_index[3] != -1) ? (source_index[3] & 0x3F) : 0);

    i += 4;
    }

  if ((return_value > 0) &&
      (destination[return_value - 1] == '\0'))
    return_value--;
  else if (return_value < size_destination)
    destination[return_value] = '\0';

  return(return_value);
  }
