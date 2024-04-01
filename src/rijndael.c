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
        for(int c = 0; c < BLOCK_COL-1; c++)                                // For every cell in row except for last one
            block[r + (c * BLOCK_ROW)] = block[r + ((c+1) * BLOCK_ROW)];    // override cell with val of next cell  
                                
        block[r + ((BLOCK_COL-1) * BLOCK_ROW)] = tmp;                       // Override last cell with val of first cell
      } 
    }   
}

void invert_shift_word(unsigned char *word, int length) {      
  unsigned char tmp = word[length-1];
  for(int i = length-1; i > 0; i--) word[i] = word[i-1];
  word[0] = tmp;
}

void invert_shift_rows(unsigned char *block) {      
    for(int r = 0; r < BLOCK_ROW; r++) {                                      // For every row
        for(int n = r; n>0; n--){                                             // - Perform rotate 'index' amount of times
            unsigned char tmp = block[r + ((BLOCK_COL-1) * BLOCK_ROW)];       // - this time start with last cell in row
            for(int c = BLOCK_COL-1; c > 0; c--)                              // - walk through cells in reversed order
              block[r + (c * BLOCK_ROW)] = block[r + ((c-1) * BLOCK_ROW)];    // - replace cell value with val of next cell 
                                 
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

void _mix_column(unsigned char *col, int length)
{	
  unsigned char total = 0x00;
  for(int i = 0; i < length; i++) total ^= col[i];

  unsigned char tmp = col[0];
  for(int i = 0; i < length-1; i++)
    col[i] ^= total ^ _xtime(col[i] ^ col[i+1]);

  col[length-1] ^= total ^ _xtime(col[length-1] ^ tmp);
}

void mix_columns(unsigned char *block) {
  for(int c = 0; c < BLOCK_COL; c++){
    unsigned char *col = &block[c*BLOCK_COL];
    _mix_column(col, 4);
  }
}

void invert_mix_word(unsigned char *word) {
  unsigned char even_xtime = _xtime(_xtime(word[0] ^ word[2]));
  for(int i=0; i<4; i+=2) word[i] ^= even_xtime;

  unsigned char uneven_xtime = _xtime(_xtime(word[1] ^ word[3]));
  for(int i=1; i<4; i+=2) word[i] ^= uneven_xtime;
}

void invert_mix_columns(unsigned char *block) {
  for(int i = 0; i < BLOCK_COL; i++) 
    invert_mix_word(&block[i*4]);
  
  mix_columns(block);
}

/*
 * *** XOR_B Bytes ***
 */
void _XOR_B(unsigned char *a, unsigned char *b, int length) {
  for(int i = 0; i < length; i++)
    b[i] = a[i] ^ b[i];
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
  int size = (KEY_COL < BLOCK_COL) ? KEY_COL : BLOCK_COL;

  for (int r = 0; r < BLOCK_ROW; r++){
    unsigned char *block_col = &block[r*BLOCK_COL];
    unsigned char *key_col = &round_key[r*KEY_COL];
    _XOR_B(key_col, block_col, size);
  }

}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key) {
  unsigned char *round_key = malloc(sizeof(unsigned char) * ((KEY_COL * KEY_ROW) * 11)); // 176

  // row 0-3
  memcpy(round_key, cipher_key, (KEY_COL * KEY_ROW));
  for(int i = 4; i < 44;i++) {
    unsigned char *col = &round_key[i * KEY_COL];
    unsigned char *prev_col = &round_key[(i-1) * KEY_COL];
    unsigned char *prev_block = &round_key[(i-4) * KEY_COL]; // I-4

    memcpy(col, prev_col, KEY_COL);

    if(i%4 == 0) {
      shift_word(col, KEY_COL); 
      _sub_word(col, S_BOX); 
      col[0] ^= R_CON[i/4];  
    }
    _XOR_B(prev_block, col, KEY_COL);
  }

  return round_key;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  int block_size = (BLOCK_ROW * BLOCK_COL);

  unsigned char *output = (unsigned char *) malloc(sizeof(unsigned char) * block_size);
  unsigned char *round_keys = expand_key(key);

  // Init round
  memcpy(output, plaintext, block_size);
  add_round_key(output, key);

  for(int i = 1; i <= 10; i++) {
    unsigned char *round_key = &round_keys[(i * KEY_COL) * KEY_ROW];
    sub_bytes(output);
    shift_rows(output);
    if (i <= 9) mix_columns(output);
    add_round_key(output, round_key);
  }

  free(round_keys);
  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  int block_size = (BLOCK_ROW * BLOCK_COL);

  unsigned char *output = (unsigned char *) malloc(sizeof(unsigned char) * block_size);
  unsigned char *round_keys = expand_key(key);

  // Init round
  memcpy(output, ciphertext, block_size);
  
  for(int i = 10; i > 0; i--) {
    unsigned char *round_key = &round_keys[(i * KEY_COL) * KEY_ROW];
    add_round_key(output, round_key);
    if (i <= 9) invert_mix_columns(output);
    invert_shift_rows(output);
    invert_sub_bytes(output);
  }

  add_round_key(output, round_keys);

  free(round_keys);
  return output;
}

void cleanup(unsigned char *ptr) {
  free(ptr);
}