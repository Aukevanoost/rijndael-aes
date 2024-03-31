#include <stdio.h>
#include <stdlib.h>

int BLOCK_ROW = 4;
int BLOCK_COL = 4;

void _print_list(unsigned char *word) {
    printf("%02X:%02X:%02X:%02X\n", word[0], word[1], word[2], word[3]);
}

void _print_ref(unsigned char **word) {
    printf("%02X:%02X:%02X:%02X\n", *word[0], *word[1], *word[2], *word[3]);
}

void _rotate(unsigned char **list, int length, signed int spots) {
  while (spots != 0){
    int shift = (spots < 0) ? -1 : 1;

    int offset = (length + shift);
    unsigned char temp = *list[offset % length];

    for(int i = 0; i < (length-1); i++){
      int idx = offset + (i*shift);

      *list[idx % length] = *list[(idx + shift) % length];
    }

    *list[(offset - shift) % length] = temp;
    spots -= shift;
  }
}

void shift_columns(unsigned char *block) {
    unsigned char *column[BLOCK_COL];
    
    for(int r = 0; r < BLOCK_ROW; r++) _print_list(&block[r*4]);
    
    for (int r = 0; r < BLOCK_ROW; r++) {
        for(int c = 0; c < BLOCK_COL; c++) column[c] = &block[r + (c * BLOCK_COL)];
        printf("-------------------------- \n");
        _print_ref(column);
        _rotate(column, BLOCK_COL, -r);
        _print_ref(column);
    } 
    
    printf("-------------------------- \n");
    for(int r = 0; r < BLOCK_ROW; r++) _print_list(&block[r*4]);
}

int main() {
    unsigned char test[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
    shift_columns(test);
    return 0;
} 