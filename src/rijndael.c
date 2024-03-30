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
  for(int r = 0; r < BLOCK_ROW; r++){
    _sub_word(&block[r * BLOCK_COL], &S_BOX);
  }
}

void invert_sub_bytes(unsigned char *block) {
    // for(int r = 0; r < BLOCK_ROW; r++)
    //   _sub_word(block[r*BLOCK_COL], S_BOX_INV);
}

/*
 * *** Step 2. ShiftRows ***
 */

//pos = left-shift, neg = right-shift
void _rot_word(unsigned char *word, signed int spots) {
  
  while (spots != 0){
    int shift = (spots < 0) ? -1 : 1;

    // Starting point:
    // - left-shift = word[1]
    // - right-shift = word[3] 
    int offset = (BLOCK_COL + shift);
    unsigned char temp = word[offset % BLOCK_COL];

    // Loop through 0, 1, 2 because 3 will receive temp 
    for(int i = 0; i < (BLOCK_COL-1); i++){
      // reverses the loop if shift is right
      int idx = offset + (i*shift);

      // Shifts an index to the left (+1) or right (-1) depending on shift
      word[idx % BLOCK_COL] = word[(idx + shift) % BLOCK_COL];
    }

    // (starting-point - shift) will receive temp  
    word[(offset - shift) % BLOCK_COL] = temp;
    spots -= shift;
  }
}

void shift_rows(unsigned char *block) {
  for(int r = 0; r < BLOCK_ROW; r++)
    _rot_word(&block[r*BLOCK_COL], -r);
}

void invert_shift_rows(unsigned char *block) {
  for(int r = 0; r < BLOCK_ROW; r++)
    _rot_word(&block[r*BLOCK_COL], r);
}




/*
 * *** Step 3. MixColumns ***
 */
void mix_columns(unsigned char *block) {
  // TODO: Implement me!
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