#ifndef __LED_BITSLICED_H__
#define __LED_BITSLICED_H__

#include "types.h"

// ####################################
// declarations

typedef struct
{
    u64 value[64];
} bitsliced_state;

/*
 * Converts 64 plaintexts of each 64 bit into the bitsliced representation.
 * state[0] contains all MSBs.
 * The bits of plaintext[0] fill the MSBs of the state registers.
 *
 * This way, the LED state-matrix can be written as:
 * | s[ 0]s[ 1]s[ 2]s[ 3]   s[ 4]s[ 5]s[ 6]s[ 7]   s[ 8]s[ 9]s[10]s[11]   s[12]s[13]s[14]s[15] |
 * | s[16]s[17]s[18]s[19]   s[20]s[21]s[22]s[23]   s[24]s[25]s[26]s[27]   s[28]s[29]s[30]s[31] |
 * | s[32]s[33]s[34]s[35]   s[36]s[37]s[38]s[39]   s[40]s[41]s[42]s[43]   s[44]s[45]s[46]s[47] |
 * | s[48]s[49]s[50]s[51]   s[52]s[53]s[54]s[55]   s[56]s[57]s[58]s[59]   s[60]s[61]s[62]s[63] |
 *
 *
 * @param[out] state - the state to fill
 * @param[in] plaintext - an array containing 64 plaintexts
 */
void convert_to_bitsliced_state(bitsliced_state* state, const u64 plaintext[64]);

/*
 * Encrypts a bitsliced state using LED-64-128.
 *
 * @param[inout] state - the state to encrypt
 * @param[in] key - the 128-bit key, split in two halves: K1 = key[0], K2 = key[1]
 */
void encrypt_bitsliced(bitsliced_state* state, const u64 key[2]);

/*
 * Converts a bitsliced state into 64 ciphertexts.
 * Inverts convert_to_bitsliced_state if invoked without any steps in between.
 *
 * @param[out] ciphertext - the array to convert into
 * @param[in] state - the bitsliced state
 */
void convert_from_bitsliced_state(u64 ciphertext[64], const bitsliced_state* state);
#endif
