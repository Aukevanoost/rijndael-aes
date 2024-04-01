
int BLOCK_ROW_SIZE = 5;
int BLOCK_COL_SIZE = 4;

void print_matrix(unsigned char *word) {
    for(int r = 0; r < BLOCK_ROW_SIZE; r++) {
        for(int c = 0; c < BLOCK_COL_SIZE; c++){
            printf("%02X ", word[r + (c * BLOCK_ROW_SIZE)]);
        }
        printf("\n");
    }
}

int main() {
    unsigned char test[20] = {
        0x00,0x01,0x02,0x03,
        0x04,0x05,0x06,0x07, 
        0x08,0x09,0x10,0x11, 
        0x12,0x13,0x14,0x15, 
        0x16,0x17,0x18,0x19,  
    };
    _print_matrix(test);
    printf("--------------\n");
    return 0;
} 
