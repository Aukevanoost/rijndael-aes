/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
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

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

#endif
