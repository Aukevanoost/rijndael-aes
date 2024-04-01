 /* ***

 * * * * * * * * * * * * * * * * * * * * * * * * 
 * @Aukevanoost                                *
 * AES Encryption  | 128 bit                   *
 * * * * * * * * * * * * * * * * * * * * * * * * 

 *** TERMINOLOGY ***
 Word:      A list of bytes, most commonly referred as a column
 Column:    A vertical list of bytes in the 'block'
 Row:       A horizontal list of bytes in the 'block'
 Block:     A square/rectangle representation of bytes. Could for example be the plaintext or the ciphertext

 *** BLOCK INDEX FORMAT ***
      00 04 08 12   ^
      01 05 09 13  column
      02 06 07 14   V
      03 07 08 15
       <- row ->
*/

#include <stdlib.h>
#include <stdio.h>

#include "lookup_table.c"
#include "rijndael.h"

/*
 * *** Step 1. SubBytes ***
 */
void _sub_word(unsigned char *word, int length, unsigned char* lookup_table) {
  for(int i = 0; i < length; i++)                                         // For each byte in word
    word[i] = (unsigned char) (lookup_table[word[i]]);                    // replace with byte from lookup table
}

void sub_bytes(unsigned char *block) {
  for(int r = 0; r < BLOCK_ROW_SIZE; r++)                                 // For each row in block
    _sub_word(&block[r * BLOCK_COL_SIZE], BLOCK_COL_SIZE, &S_BOX);        // Substitute column using S_BOX
}

void invert_sub_bytes(unsigned char *block) {
  for(int r = 0; r < BLOCK_ROW_SIZE; r++)                                 // For each row in block
    _sub_word(&block[r * BLOCK_COL_SIZE], BLOCK_COL_SIZE, &S_BOX_INV);    // Substitute column using S_BOX_INV
}

/*
 * *** Step 2. ShiftRows ***
 */

void shift_word(unsigned char *word, int length) {      
  unsigned char tmp = word[0];                                            // Temporary store first variable
  for(int i = 0; i < (length-1); i++) word[i] = word[i+1];                // Replace all vars but last
  word[length-1] = tmp;                                                   // Replace last var with first var
}

/*
 * Most efficient way to shift rows, 
 * for a more generic and readable implementation check shift_rows.c
 *
 * <-rows->
 * 01 04 07  ^       // formula: Index = [row_index + (columns * col_index)]
 * 02 05 08 cols     // As seen on the left, 
 * 03 06 09  v       // the matrix format is a bit funky
 * 
*/
void shift_rows(unsigned char *block) { 
    for(int r = 0; r < BLOCK_ROW_SIZE; r++) {                                           // For every row
      for(int n = r; n>0; n--){                                                         // perform rotate 'index' amount of times
        unsigned char tmp = block[r];                                                   // save first entry as temp 
        for(int c = 0; c < BLOCK_COL_SIZE-1; c++)                                       // For every cell in row except for last one
            block[r + (c * BLOCK_COL_SIZE)] = block[r + ((c+1) * BLOCK_COL_SIZE)];      // override cell with val of next cell  
                                
        block[r + ((BLOCK_ROW_SIZE-1) * BLOCK_COL_SIZE)] = tmp;                         // Override last cell with val of first cell
      } 
    }   
}

void invert_shift_word(unsigned char *word, int length) {      
  unsigned char tmp = word[length-1];
  for(int i = length-1; i > 0; i--) word[i] = word[i-1];
  word[0] = tmp;
}

void invert_shift_rows(unsigned char *block) {      
    for(int r = 0; r < BLOCK_ROW_SIZE; r++) {                                           // For every row
        for(int n = r; n>0; n--){                                                       // - Perform rotate 'index' amount of times
            unsigned char tmp = block[r + ((BLOCK_ROW_SIZE-1) * BLOCK_COL_SIZE)];       // - this time start with last cell in row
            for(int c = BLOCK_COL_SIZE-1; c > 0; c--)                                   // - walk through cells in reversed order
              block[r + (c * BLOCK_COL_SIZE)] = block[r + ((c-1) * BLOCK_COL_SIZE)];    // - replace cell value with val of next cell 
                                 
            block[r] = tmp;                                                             // - replace first cell with val of last cell
        } 
    }   
}

/*
 * *** Step 3. MixColumns ***
 */

 

// [ref: https://web.archive.org/web/20100626212235/http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c]
// Balanced out bit-check with redundant '& 0xFF' to prevent timed attacks
unsigned char _xtime(int x) {
    return (x & 0x80) ? ((x << 1) ^ 0x1b) : ((x<<1) & 0xFF);                       
}

// Multiplies a byte by 2 in the Galois field
// Full explanation: The design of Rijndael 4.1.2
void _mix_word(unsigned char *word, int length)
{	
  unsigned char total = 0x00;                                     
  for(int i = 0; i < length; i++) total ^= word[i];                                      // Take XOR of a word

  unsigned char tmp = word[0];                                                           // Store first value of word in tmp
  for(int i = 0; i < length-1; i++)                                                      // For each byte in word
    word[i] ^= total ^ _xtime(word[i] ^ word[i+1]);                                      // (xtime lookup of cell XOR next cell) XOR total

  word[length-1] ^= total ^ _xtime(word[length-1] ^ tmp);                                // (xtime lookup of cell XOR first cell) XOR total
}

void mix_columns(unsigned char *block) {
  for(int r = 0; r < BLOCK_ROW_SIZE; r++){                                               // foreach row in block
    _mix_word(&block[r*BLOCK_COL_SIZE], BLOCK_COL_SIZE);                                 // Mix column
  }
}

// Full explanation: The design of Rijndael 4.1.3
void invert_mix_word(unsigned char *word, int length) { 
  unsigned char even_xtime = _xtime(_xtime(word[0] ^ word[2]));                         
  for(int i=0; i<length; i+=2) word[i] ^= even_xtime;

  unsigned char uneven_xtime = _xtime(_xtime(word[1] ^ word[3]));
  for(int i=1; i<length; i+=2) word[i] ^= uneven_xtime;
}

void invert_mix_columns(unsigned char *block) {
  for(int r = 0; r < BLOCK_ROW_SIZE; r++)                                               // foreach row in block
    invert_mix_word(&block[r * BLOCK_COL_SIZE], BLOCK_COL_SIZE);                        // Prepare columns
  
  mix_columns(block);                                                                   // Mix columns
}

/*
 * *** XOR_B Bytes ***
 */
void _XOR_B(unsigned char *a, unsigned char *b, int length) {
  for(int i = 0; i < length; i++)                                     // For each byte in word
    b[i] = a[i] ^ b[i];                                               // B = A XOR B
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
  int row_size = (KEY_ROW_SIZE < BLOCK_ROW_SIZE) ? KEY_ROW_SIZE : BLOCK_ROW_SIZE;   // Choose smallest provided rowsize, KEY or BLOCK
  int col_size = (KEY_COL_SIZE < BLOCK_COL_SIZE) ? KEY_COL_SIZE : BLOCK_COL_SIZE;   // Choose smallest provided colsize, KEY or BLOCK

  for (int r = 0; r < row_size; r++)                                                // For each row
    _XOR_B( &round_key[r * col_size],  &block[r * col_size],  col_size);            // block_col XOR roundkey_col
}

/*
 * Will expand the key-block (16-byte) to 11 keys (176-byte)
*/
unsigned char *expand_key(unsigned char *cipher_key) {
  int KEY_BLOCK_SIZE = KEY_COL_SIZE * KEY_ROW_SIZE;

  unsigned char *round_key = malloc(sizeof(unsigned char) * (KEY_BLOCK_SIZE * (ROUNDS + 1)));   // Allocate space for expanded key

  memcpy(round_key, cipher_key, KEY_BLOCK_SIZE);                                    // Copy cipher_key into first block
  for(int c = KEY_COL_SIZE; c < (KEY_COL_SIZE * (ROUNDS + 1)); c++) {               // For all other blocks, iterate through cols

    unsigned char *col = &round_key[c * KEY_COL_SIZE];                              // Ref to 'W'   current column
    unsigned char *prev_col = &round_key[(c-1) * KEY_COL_SIZE];                     // Ref to 'W-1' prev column
    unsigned char *prev_block = &round_key[(c - KEY_COL_SIZE) * KEY_COL_SIZE];      // Ref to 'W-4' first column of prev block

    memcpy(col, prev_col, KEY_COL_SIZE);                                            // Copy 'W-1' into 'W'

    if(c % KEY_COL_SIZE == 0) {                                                     // For every first column of block
      shift_word(col, KEY_COL_SIZE);                                                // 1) shift column
      _sub_word(col, KEY_COL_SIZE, S_BOX);                                          // 2) substitute bytes (cells)
      col[0] ^= R_CON[c / KEY_COL_SIZE];                                            // 3) Use R_CON to XOR first byte (cell)
    }
    _XOR_B(prev_block, col, KEY_COL_SIZE);                                          // XOR 'prev_col' into current 'col'
  }

  return round_key;
}

/*
 * AES 128-bit encryption
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {    
  int BLOCK_SIZE = (BLOCK_ROW_SIZE * BLOCK_COL_SIZE);                               
  int KEY_SIZE = (KEY_ROW_SIZE * KEY_COL_SIZE);                               

  unsigned char *output = malloc(sizeof(unsigned char) * BLOCK_SIZE);               // Allocate space for block
  unsigned char *round_keys = expand_key(key);                                      // Expand 16-bit key to 176-bit key (1 per round)

  memcpy(output, plaintext, BLOCK_SIZE);                                            // 'Init round', store plaintext in block 
  add_round_key(output, key);                                                       // 1) XOR cipherkey into plaintext

  for(int i = 1; i <= ROUNDS; i++) {                                                // For every round:
    unsigned char *round_key = &round_keys[i * KEY_SIZE];                           // get roundKey
    sub_bytes(output);                                                              // 1) SubBytes block
    shift_rows(output);                                                             // 2) ShiftRows block
    if (i <= ROUNDS-1) mix_columns(output);                                         // 3) for all but last round, MixColumns block
    add_round_key(output, round_key);                                               // 4) XOR roundkey into block
  }

  free(round_keys);                                                                 // Deallocate the roundkeys
  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key) {
  int BLOCK_SIZE = (BLOCK_ROW_SIZE * BLOCK_COL_SIZE);
  int KEY_SIZE = (KEY_ROW_SIZE * KEY_COL_SIZE);                               

  unsigned char *output = malloc(sizeof(unsigned char) * BLOCK_SIZE);               // Allocate space for block
  unsigned char *round_keys = expand_key(key);                                      // Expand 16-bit key to 176-bit key (1 per round)

  // Init round
  memcpy(output, ciphertext, BLOCK_SIZE);                                           // Store cipherkey in block
  
  for(int i = ROUNDS; i > 0; i--) {                                                 // Reverse 'encrypt' steps, for every round:
    unsigned char *round_key = &round_keys[(i * KEY_COL_SIZE) * KEY_ROW_SIZE];      // get roundKey
    add_round_key(output, round_key);                                               // 4) XOR roundkey into block
    if (i <= ROUNDS-1) invert_mix_columns(output);                                  // 3) for all but last round, MixColumns block
    invert_shift_rows(output);                                                      // 2) ShiftRows block
    invert_sub_bytes(output);                                                       // 1) SubBytes block
  }

  add_round_key(output, round_keys);                                                // reversed 'Init round', XOR roundkey with block

  free(round_keys);                                                                 // Free roundkeys
  return output;
}

void cleanup(unsigned char *ptr) {
  free(ptr);                                                                        // Used by test-suite to remove bytes from the heap
}