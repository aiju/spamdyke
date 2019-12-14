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
#include "md5.h"

#ifndef WITHOUT_CONFIG_TEST

/*
 * The MD5 algorithm is described in RFC 1321.
 */

/*
 * From RFC 1321, page 4.
 */
#define F(X,Y,Z)                        (((X) & (Y)) | ((~(X)) & (Z)))
#define G(X,Y,Z)                        (((X) & (Z)) | ((Y) & (~(Z))))
#define H(X,Y,Z)                        (((X) ^ (Y)) ^ (Z))
#define I(X,Y,Z)                        ((Y) ^ ((X) | (~(Z))))

/*
 * From RFC 1321, page 5.
 */
#define ROUND1_ABCD(a,b,c,d,Xk,s,Ti)    ((b) + lshift((a) + F((b),(c),(d)) + (Xk) + (Ti), (s)))
#define ROUND2_ABCD(a,b,c,d,Xk,s,Ti)    ((b) + lshift((a) + G((b),(c),(d)) + (Xk) + (Ti), (s)))
#define ROUND3_ABCD(a,b,c,d,Xk,s,Ti)    ((b) + lshift((a) + H((b),(c),(d)) + (Xk) + (Ti), (s)))
#define ROUND4_ABCD(a,b,c,d,Xk,s,Ti)    ((b) + lshift((a) + I((b),(c),(d)) + (Xk) + (Ti), (s)))

#define PAD_BLOCK                       (unsigned char []){ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
                                                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }

/*
 * The values in this table come from the example code in RFC 1321, pages 13-14.
 */
#define SINE_TABLE                      (uint32_t []){ 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, \
                                                       0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, \
                                                       0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8, \
                                                       0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, \
                                                       0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, \
                                                       0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, \
                                                       0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1, \
                                                       0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 }

/*
 * These values come from RFC 1321, page 4.
 */
#define INITIALIZE_A                    0x67452301
#define INITIALIZE_B                    0xEFCDAB89
#define INITIALIZE_C                    0x98BADCFE
#define INITIALIZE_D                    0x10325476

/*
 * Converts a sequence of 32 bit integers from native format to little endian
 * format (least significant byte first).
 *
 * Expects:
 *   destination's allocated size must equal length_bytes
 *
 * Return value:
 *   source if the value was already in little-endian order.  destination if the value was converted or always_copy != 0
 */
unsigned char *htole(unsigned char *destination, uint32_t *source, long length_bytes, int always_copy)
  {
  static int little_endian = -1;
  void *return_value;
  int i;
  int j;
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

  if (!little_endian ||
      always_copy)
    {
    for (i = 0; i < (length_bytes / 4); i++)
      {
      for (j = 0; j < 4; j++)
        convert.string[j] = (unsigned char)((source[i] >> (j * 8)) & 0xFF);
      for (j = 0; j < 4; j++)
        destination[(i * 4) + j] = convert.string[j];
      }
    if ((length_bytes % 4) > 0)
      {
      for (j = 0; j < 4; j++)
        convert.string[j] = (unsigned char)((source[i] >> (j * 8)) & 0xFF);
      for (j = 0; j < (length_bytes % 4); j++)
        destination[(i * 4) + j] = convert.string[j];
      }

    return_value = destination;
    }
  else
    return_value = source;

  return((unsigned char *)return_value);
  }

/*
 * Return value:
 *   X circular left-shifted n positions
 */
inline uint32_t lshift(uint32_t X, int n)
  {
  return((n > 0) ? ((X << n) | (X >> (32 - n))) : X);
  }

/*
 * Return value:
 *   destination
 */
unsigned char *md5(unsigned char destination[16], unsigned char *source, uint64_t source_len)
  {
  uint32_t *T;
  unsigned int i;
  int pad_len;
  unsigned char padding[73];
  unsigned char padded_source[64];
  unsigned char converted_source[64];
  uint32_t convert_array[16];
  uint32_t A;
  uint32_t B;
  uint32_t C;
  uint32_t D;
  uint32_t AA;
  uint32_t BB;
  uint32_t CC;
  uint32_t DD;
  uint32_t *source_block;

  T = SINE_TABLE;

  /*
   * Step 1, RFC 1321, page 3.
   */
  pad_len = 56 - (source_len % 64);
  if (pad_len <= 0)
    pad_len += 64;

  memcpy(padding, PAD_BLOCK, pad_len);

  /*
   * Step 2, RFC 1321, page 3.
   */
  convert_array[0] = (source_len << 3) & 0xFFFFFFFF;
  convert_array[1] = ((source_len >> 29) & 0xFFFFFFFF) + ((source_len & 0xE0000000) ? 1 : 0);
  htole(padding + pad_len, convert_array, 8, 1);
  pad_len += 8;

  /*
   * Step 3, RFC 1321, page 3-4.
   */
  A = INITIALIZE_A;
  B = INITIALIZE_B;
  C = INITIALIZE_C;
  D = INITIALIZE_D;

  /*
   * Step 4, RFC 1321, page 4.
   */
  for (i = 0; i <= (((source_len + pad_len) / 64) - 1); i++)
    {
    if (((i + 1) * 64) > source_len)
      {
      if ((i * 64) > source_len)
        memcpy(padded_source, padding + (pad_len % 64), 64);
      else
        {
        memcpy(padded_source, source + (i * 64), source_len - (i * 64));
        memcpy(padded_source + (source_len - (i * 64)), padding, (pad_len == 64) ? 64 : (pad_len % 64));
        }

      source_block = (uint32_t *)htole(converted_source, (uint32_t *)padded_source, 64, 0);
      }
    else
      source_block = (uint32_t *)htole(padded_source, (uint32_t *)(source + (i * 64)), 64, 0);

    AA = A;
    BB = B;
    CC = C;
    DD = D;

    /*
     * Step 4, round 1, RFC 1321, page 5.
     */
    A = ROUND1_ABCD(A, B, C, D, source_block[ 0],  7, T[ 0]);
    D = ROUND1_ABCD(D, A, B, C, source_block[ 1], 12, T[ 1]);
    C = ROUND1_ABCD(C, D, A, B, source_block[ 2], 17, T[ 2]);
    B = ROUND1_ABCD(B, C, D, A, source_block[ 3], 22, T[ 3]);

    A = ROUND1_ABCD(A, B, C, D, source_block[ 4],  7, T[ 4]);
    D = ROUND1_ABCD(D, A, B, C, source_block[ 5], 12, T[ 5]);
    C = ROUND1_ABCD(C, D, A, B, source_block[ 6], 17, T[ 6]);
    B = ROUND1_ABCD(B, C, D, A, source_block[ 7], 22, T[ 7]);

    A = ROUND1_ABCD(A, B, C, D, source_block[ 8],  7, T[ 8]);
    D = ROUND1_ABCD(D, A, B, C, source_block[ 9], 12, T[ 9]);
    C = ROUND1_ABCD(C, D, A, B, source_block[10], 17, T[10]);
    B = ROUND1_ABCD(B, C, D, A, source_block[11], 22, T[11]);

    A = ROUND1_ABCD(A, B, C, D, source_block[12],  7, T[12]);
    D = ROUND1_ABCD(D, A, B, C, source_block[13], 12, T[13]);
    C = ROUND1_ABCD(C, D, A, B, source_block[14], 17, T[14]);
    B = ROUND1_ABCD(B, C, D, A, source_block[15], 22, T[15]);

    /*
     * Step 4, round 2, RFC 1321, page 5.
     */
    A = ROUND2_ABCD(A, B, C, D, source_block[ 1],  5, T[16]);
    D = ROUND2_ABCD(D, A, B, C, source_block[ 6],  9, T[17]);
    C = ROUND2_ABCD(C, D, A, B, source_block[11], 14, T[18]);
    B = ROUND2_ABCD(B, C, D, A, source_block[ 0], 20, T[19]);

    A = ROUND2_ABCD(A, B, C, D, source_block[ 5],  5, T[20]);
    D = ROUND2_ABCD(D, A, B, C, source_block[10],  9, T[21]);
    C = ROUND2_ABCD(C, D, A, B, source_block[15], 14, T[22]);
    B = ROUND2_ABCD(B, C, D, A, source_block[ 4], 20, T[23]);

    A = ROUND2_ABCD(A, B, C, D, source_block[ 9],  5, T[24]);
    D = ROUND2_ABCD(D, A, B, C, source_block[14],  9, T[25]);
    C = ROUND2_ABCD(C, D, A, B, source_block[ 3], 14, T[26]);
    B = ROUND2_ABCD(B, C, D, A, source_block[ 8], 20, T[27]);

    A = ROUND2_ABCD(A, B, C, D, source_block[13],  5, T[28]);
    D = ROUND2_ABCD(D, A, B, C, source_block[ 2],  9, T[29]);
    C = ROUND2_ABCD(C, D, A, B, source_block[ 7], 14, T[30]);
    B = ROUND2_ABCD(B, C, D, A, source_block[12], 20, T[31]);

    /*
     * Step 4, round 3, RFC 1321, page 5.
     */
    A = ROUND3_ABCD(A, B, C, D, source_block[ 5],  4, T[32]);
    D = ROUND3_ABCD(D, A, B, C, source_block[ 8], 11, T[33]);
    C = ROUND3_ABCD(C, D, A, B, source_block[11], 16, T[34]);
    B = ROUND3_ABCD(B, C, D, A, source_block[14], 23, T[35]);

    A = ROUND3_ABCD(A, B, C, D, source_block[ 1],  4, T[36]);
    D = ROUND3_ABCD(D, A, B, C, source_block[ 4], 11, T[37]);
    C = ROUND3_ABCD(C, D, A, B, source_block[ 7], 16, T[38]);
    B = ROUND3_ABCD(B, C, D, A, source_block[10], 23, T[39]);

    A = ROUND3_ABCD(A, B, C, D, source_block[13],  4, T[40]);
    D = ROUND3_ABCD(D, A, B, C, source_block[ 0], 11, T[41]);
    C = ROUND3_ABCD(C, D, A, B, source_block[ 3], 16, T[42]);
    B = ROUND3_ABCD(B, C, D, A, source_block[ 6], 23, T[43]);

    A = ROUND3_ABCD(A, B, C, D, source_block[ 9],  4, T[44]);
    D = ROUND3_ABCD(D, A, B, C, source_block[12], 11, T[45]);
    C = ROUND3_ABCD(C, D, A, B, source_block[15], 16, T[46]);
    B = ROUND3_ABCD(B, C, D, A, source_block[ 2], 23, T[47]);

    /*
     * Step 4, round 4, RFC 1321, page 5.
     */
    A = ROUND4_ABCD(A, B, C, D, source_block[ 0],  6, T[48]);
    D = ROUND4_ABCD(D, A, B, C, source_block[ 7], 10, T[49]);
    C = ROUND4_ABCD(C, D, A, B, source_block[14], 15, T[50]);
    B = ROUND4_ABCD(B, C, D, A, source_block[ 5], 21, T[51]);

    A = ROUND4_ABCD(A, B, C, D, source_block[12],  6, T[52]);
    D = ROUND4_ABCD(D, A, B, C, source_block[ 3], 10, T[53]);
    C = ROUND4_ABCD(C, D, A, B, source_block[10], 15, T[54]);
    B = ROUND4_ABCD(B, C, D, A, source_block[ 1], 21, T[55]);

    A = ROUND4_ABCD(A, B, C, D, source_block[ 8],  6, T[56]);
    D = ROUND4_ABCD(D, A, B, C, source_block[15], 10, T[57]);
    C = ROUND4_ABCD(C, D, A, B, source_block[ 6], 15, T[58]);
    B = ROUND4_ABCD(B, C, D, A, source_block[13], 21, T[59]);

    A = ROUND4_ABCD(A, B, C, D, source_block[ 4],  6, T[60]);
    D = ROUND4_ABCD(D, A, B, C, source_block[11], 10, T[61]);
    C = ROUND4_ABCD(C, D, A, B, source_block[ 2], 15, T[62]);
    B = ROUND4_ABCD(B, C, D, A, source_block[ 9], 21, T[63]);

    A += AA;
    B += BB;
    C += CC;
    D += DD;
    }

  convert_array[0] = A;
  convert_array[1] = B;
  convert_array[2] = C;
  convert_array[3] = D;
  htole(destination, convert_array, 16, 1);

  return(destination);
  }

#endif /* WITHOUT_CONFIG_TEST */
