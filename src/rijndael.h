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

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])

#define BLOCK_ROW_SIZE 4
#define BLOCK_COL_SIZE 4

#define KEY_ROW_SIZE 4
#define KEY_COL_SIZE 4

#define ROUNDS 10

unsigned char *expand_key(unsigned char *cipher_key);

unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

#endif
