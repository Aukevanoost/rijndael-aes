 /*
 * D23124832 - Auke van Oostenbrugge
 * AES Encryption
 */

#include <stdlib.h>
#include <stdio.h>

#include "lookup_table.c"

#include "rijndael.h"



/*
 * *** Step 1. SubBytes ***
 */
void _sub_word(unsigned char *word, unsigned char* table) {
  for(int c = 0; c < BLOCK_COL; c++)
    word[c] = (unsigned char) (table[word[c]]);
}

void sub_bytes(unsigned char *block) {
  for(int r = 0; r < BLOCK_ROW; r++)
    _sub_word(&block[r * BLOCK_COL], &S_BOX);
}

void invert_sub_bytes(unsigned char *block) {
  for(int r = 0; r < BLOCK_ROW; r++)
    _sub_word(&block[r * BLOCK_COL], &S_BOX_INV);
}

/*
 * *** Step 2. ShiftRows ***
 */

void shift_word(unsigned char *word, int length) {      
  unsigned char tmp = word[0];
  for(int i = 0; i < (length-1); i++) word[i] = word[i+1];
  word[length-1] = tmp;
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
    for(int r = 0; r < BLOCK_ROW; r++) {                                        // For every row
        for(int n = r; n>0; n--){                                               // perform rotate 'index' amount of times
            unsigned char tmp = block[r];                                       // save first entry as temp 
            for(int c = 0; c < BLOCK_COL-1; c++){                               // For every cell in row except for last one
                block[r + (c * BLOCK_ROW)] = block[r + ((c+1) * BLOCK_ROW)];    // override cell with val of next cell  
            }                        
            block[r + ((BLOCK_COL-1) * BLOCK_ROW)] = tmp;                       // Override last cell with val of first cell
        } 
    }   
}

void shift_word_inv(unsigned char *word, int length) {      
  unsigned char tmp = word[length-1];
  for(int i = length-1; i > 0; i--) word[i] = word[i-1];
  word[0] = tmp;
}

void invert_shift_rows(unsigned char *block) {      
    for(int r = 0; r < BLOCK_ROW; r++) {                                      // For every row
        for(int n = r; n>0; n--){                                             // - Perform rotate 'index' amount of times
            unsigned char tmp = block[r + ((BLOCK_COL-1) * BLOCK_ROW)];       // - this time start with last cell in row
            for(int c = BLOCK_COL-1; c > 0; c--){                             // - walk through cells in reversed order
                block[r + (c * BLOCK_ROW)] = block[r + ((c-1) * BLOCK_ROW)];  // - replace cell value with val of next cell 
            }                        
            block[r] = tmp;                                                   // - replace first cell with val of last cell
        } 
    }   
}

/*
 * *** Step 3. MixColumns ***
 */
unsigned char _xtime(int x) {
    return (x & 0x80) ? ((x << 1) ^ 0x1b) : (x<<1);
}

void _mix_column(unsigned char *word)
{	
  unsigned char total = 0x00;
  for(int i = 0; i < BLOCK_COL; i++) total ^= word[i];

  unsigned char tmp = word[0];
  for(int i = 0; i < BLOCK_COL-1; i++)
    word[i] ^= total ^ _xtime(word[i] ^ word[i+1]);

  word[BLOCK_COL-1] ^= total ^ _xtime(word[BLOCK_COL-1] ^ tmp);
}

void mix_columns(unsigned char *block) {
  for(int r = 0; r < BLOCK_ROW; r++){
    unsigned char *test = &block[r*BLOCK_COL];
    _mix_column(test);
  }
}

void invert_mix_columns(unsigned char *block) {
  // TODO: Implement me!
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
  // TODO: Implement me!
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key) {
  unsigned char *round_key = malloc(16 * 1); // 176

  // row 0-3
  for (int i = 0; i < 16; i++) 
    round_key[i] = cipher_key[i]; 
  
 

  // array of 32-bit words (columns)  [0..43]
  // first 4 are given cipher key
  // words in positions that are multiple of 4 are calculated by 
    // A
      // - applying the rotword on the previous word Wi-1
      // - subbytes transformations on the previous word Wi-1
    // B
      // - adding XOR to result (W) and W-3
      // + a round constant Rcon(4)

  return round_key;
}


// void XORB(unsigned char *A, unsigned char *B) {
//   for(int i = 0; i < BLOCK_COL; i++)
//     B[i] = A[i] ^ B[i];
// }

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * (BLOCK_ROW * BLOCK_COL));
  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * (BLOCK_ROW * BLOCK_COL));
  return output;
}

void cleanup(unsigned char *ptr) {
  free(ptr);
}