/* ***

* * * * * * * * * * * * * * * * * * * * * * * *
* @Aukevanoost                                *
* AES Encryption  | 128 bit                   *
* * * * * * * * * * * * * * * * * * * * * * * *

*** TERMINOLOGY ***
Word:      A list of bytes, most commonly referred as a column
Column:    A vertical list of bytes in the 'block'
Row:       A horizontal list of bytes in the 'block'
Block:     A square/rectangle representation of bytes. Could for example be the
plaintext or the ciphertext

*** BLOCK INDEX FORMAT ***
     00 04 08 12   ^
     01 05 09 13  column
     02 06 07 14   V
     03 07 08 15
      <- row ->
*/

#include "rijndael.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lookup_table.c"

/*
 * *** Step 1. SubBytes ***
 */

// Loop through all the bytes in the word and substitute them for the item in
// the given lookup table
void _sub_word(unsigned char *word, int length, unsigned char *lookup_table) {
  for (int i = 0; i < length; i++)
    word[i] = (unsigned char)(lookup_table[word[i]]);
}

// For each column in block, substitute cells for items in S_BOX
void sub_bytes(unsigned char *block) {
  for (int c = 0; c < BLOCK_ROW_SIZE; c++)
    _sub_word(&block[c * BLOCK_COL_SIZE], BLOCK_COL_SIZE, S_BOX);
}

// For each column in block, substitute column using S_BOX_INV
void invert_sub_bytes(unsigned char *block) {
  for (int c = 0; c < BLOCK_ROW_SIZE; c++)
    _sub_word(&block[c * BLOCK_COL_SIZE], BLOCK_COL_SIZE, S_BOX_INV);
}

/*
 * *** Step 2. ShiftRows ***
 */

// loop through the cells in the word.
// store first variable in tmp, replace all bytes in word except last, and
// replace last with tmp value
void shift_word(unsigned char *word, int length) {
  unsigned char tmp = word[0];
  for (int i = 0; i < (length - 1); i++) word[i] = word[i + 1];
  word[length - 1] = tmp;
}

/*
 * Most efficient way to shift rows,
 * for a more generic and readable implementation check
 * hall_of_fame/shift_rows.c
 *
 * <-rows->
 * 01 04 07  ^       // formula: Index = [col_index + (columns * row_index)]
 * 02 05 08 cols     // As seen on the left,
 * 03 06 09  v       // the matrix format is a bit funky
 *
 */
void shift_rows(unsigned char *block) {
  // For every column
  for (int c = 0; c < BLOCK_ROW_SIZE; c++) {
    // perform rotate 'col_index' amount of times
    for (int n = c; n > 0; n--) {
      unsigned char tmp = block[c];
      for (int r = 0; r < BLOCK_COL_SIZE - 1; r++) {
        int cell_index = c + (r * BLOCK_COL_SIZE);
        block[cell_index] = block[cell_index + BLOCK_COL_SIZE];
      }
      // col + "offset as (rows-1) x columns" = last cell of row
      block[c + ((BLOCK_ROW_SIZE - 1) * BLOCK_COL_SIZE)] = tmp;
    }
  }
}

void invert_shift_word(unsigned char *word, int length) {
  unsigned char tmp = word[length - 1];
  for (int i = length - 1; i > 0; i--) word[i] = word[i - 1];
  word[0] = tmp;
}

void invert_shift_rows(unsigned char *block) {
  // For every column
  for (int co = 0; co < BLOCK_ROW_SIZE; co++) {
    // perform rotate 'col_index' amount of times
    for (int n = co; n > 0; n--) {
      // this time start with last cell in row
      unsigned char tmp = block[co + ((BLOCK_ROW_SIZE - 1) * BLOCK_COL_SIZE)];
      // walk through cells in reversed order
      for (int c = BLOCK_COL_SIZE - 1; c > 0; c--) {
        int cell_index = co + (c * BLOCK_COL_SIZE);
        block[cell_index] = block[cell_index - BLOCK_COL_SIZE];
      }

      // replace first cell with val of last cell
      block[co] = tmp;
    }
  }
}

/*
 * *** Step 3. MixColumns ***
 */

// [ref:
// https://web.archive.org/web/20100626212235/http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c]
// Balanced out bit-check with redundant '& 0xFF' to prevent timed attacks
unsigned char _xtime(int x) {
  return (x & 0x80) ? ((x << 1) ^ 0x1b) : ((x << 1) & 0xFF);
}

// Multiplies a byte by 2 in the Galois field
// Full explanation: The design of Rijndael 4.1.2
void _mix_word(unsigned char *word, int length) {
  // Take XOR of a word
  unsigned char total = 0x00;
  for (int i = 0; i < length; i++) total ^= word[i];

  // For each byte in word, (xtime lookup of cell XOR next cell) XOR total
  unsigned char tmp = word[0];
  for (int i = 0; i < length - 1; i++)
    word[i] ^= total ^ _xtime(word[i] ^ word[i + 1]);

  // formula: (xtime lookup of cell 'XOR' first cell) 'XOR' total
  word[length - 1] ^= total ^ _xtime(word[length - 1] ^ tmp);
}

// foreach row in block, Mix column
void mix_columns(unsigned char *block) {
  for (int c = 0; c < BLOCK_ROW_SIZE; c++) {
    _mix_word(&block[c * BLOCK_COL_SIZE], BLOCK_COL_SIZE);
  }
}

// Full explanation: The design of Rijndael 4.1.3
void invert_mix_word(unsigned char *word, int length) {
  unsigned char even_xtime = _xtime(_xtime(word[0] ^ word[2]));
  for (int i = 0; i < length; i += 2) word[i] ^= even_xtime;

  unsigned char uneven_xtime = _xtime(_xtime(word[1] ^ word[3]));
  for (int i = 1; i < length; i += 2) word[i] ^= uneven_xtime;
}

// foreach row in block, Prepare columns
void invert_mix_columns(unsigned char *block) {
  for (int r = 0; r < BLOCK_ROW_SIZE; r++)
    invert_mix_word(&block[r * BLOCK_COL_SIZE], BLOCK_COL_SIZE);

  mix_columns(block);
}

/*
 * *** XOR_B Bytes ***
 */
void _XOR_B(unsigned char *a, unsigned char *b, int length) {
  for (int i = 0; i < length; i++)  // For each byte in word
    b[i] = a[i] ^ b[i];             // B = A 'XOR' B
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
  // Choose smallest provided rowsize, KEY or BLOCK
  int row_size =
      (KEY_ROW_SIZE < BLOCK_ROW_SIZE) ? KEY_ROW_SIZE : BLOCK_ROW_SIZE;
  // Choose smallest provided colsize, KEY or BLOCK
  int col_size =
      (KEY_COL_SIZE < BLOCK_COL_SIZE) ? KEY_COL_SIZE : BLOCK_COL_SIZE;

  for (int c = 0; c < row_size; c++)
    // block_col = roundkey_col XOR block_col
    _XOR_B(&round_key[c * col_size], &block[c * col_size], col_size);
}

/*
 * Will expand the key-block (16-byte) to 11 keys (176-byte)
 */
unsigned char *expand_key(unsigned char *cipher_key) {
  int KEY_BLOCK_SIZE = KEY_COL_SIZE * KEY_ROW_SIZE;

  // Allocate space for expanded key
  unsigned char *round_key =
      malloc(sizeof(unsigned char) * (KEY_BLOCK_SIZE * (ROUNDS + 1)));

  // Copy cipher_key into first block
  memcpy(round_key, cipher_key, KEY_BLOCK_SIZE);
  // iterate through columns, start at first row after first block.
  for (int c = KEY_COL_SIZE; c < (KEY_COL_SIZE * (ROUNDS + 1)); c++) {
    // Ref to 'W' current column
    unsigned char *col = &round_key[c * KEY_COL_SIZE];
    // Ref to 'W-1' prev column
    unsigned char *prev_col = &round_key[(c - 1) * KEY_COL_SIZE];
    // Ref to 'W-4' first column of prev block
    unsigned char *prev_block = &round_key[(c - KEY_COL_SIZE) * KEY_COL_SIZE];

    memcpy(col, prev_col, KEY_COL_SIZE);

    // For every first column of block, perform shift_columns, sub_bytes and
    // RCON
    if (c % KEY_COL_SIZE == 0) {
      shift_word(col, KEY_COL_SIZE);
      _sub_word(col, KEY_COL_SIZE, S_BOX);

      // 3) Use R_CON to XOR first byte (cell)
      col[0] ^= R_CON[c / KEY_COL_SIZE];
    }

    // XOR 'prev_col' into current 'col' for all columns
    _XOR_B(prev_block, col, KEY_COL_SIZE);
  }

  return round_key;
}

/*
 * AES 128-bit encryption
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  int BLOCK_SIZE = (BLOCK_ROW_SIZE * BLOCK_COL_SIZE);
  int KEY_SIZE = (KEY_ROW_SIZE * KEY_COL_SIZE);

  // Allocate space for block
  unsigned char *output = malloc(sizeof(unsigned char) * BLOCK_SIZE);
  unsigned char *round_keys = expand_key(key);

  // 'Init round', store plaintext in block,
  memcpy(output, plaintext, BLOCK_SIZE);
  // XOR cipherkey into plaintext
  add_round_key(output, key);

  // All other rounds
  for (int i = 1; i <= ROUNDS; i++) {
    unsigned char *round_key = &round_keys[i * KEY_SIZE];
    sub_bytes(output);
    shift_rows(output);

    // For all but last round, MixColumns block
    if (i <= ROUNDS - 1) mix_columns(output);

    // XOR roundkey into block
    add_round_key(output, round_key);
  }

  // Deallocate the roundkeys
  free(round_keys);
  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  int BLOCK_SIZE = (BLOCK_ROW_SIZE * BLOCK_COL_SIZE);
  int KEY_SIZE = (KEY_ROW_SIZE * KEY_COL_SIZE);

  // Allocate space for block
  unsigned char *output = malloc(sizeof(unsigned char) * BLOCK_SIZE);
  // Expand 16-bit key to 176-bit key (1 block per round)
  unsigned char *round_keys = expand_key(key);

  // Init round
  memcpy(output, ciphertext, BLOCK_SIZE);  // Store cipherkey in block

  // Reverse 'encrypt' steps, for every round:
  for (int i = ROUNDS; i > 0; i--) {
    // get roundKey
    unsigned char *round_key = &round_keys[(i * KEY_COL_SIZE) * KEY_ROW_SIZE];
    add_round_key(output, round_key);

    // For all but last round, MixColumns block
    if (i <= ROUNDS - 1) invert_mix_columns(output);

    invert_shift_rows(output);
    invert_sub_bytes(output);
  }

  // reversed 'Init round', XOR roundkey with block
  add_round_key(output, round_keys);

  free(round_keys);  // Free roundkeys
  return output;
}

void cleanup(unsigned char *ptr) {
  free(ptr);  // Used by test-suite to remove bytes from the heap
}