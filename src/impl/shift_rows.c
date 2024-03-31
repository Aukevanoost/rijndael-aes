/**
* ******** SHIFT ROWS IMPLEMENTATION ********
* Very compact, no duplicate code however, not very efficient. 
* So omitted but presented anyway
* 
*/

// A facade for _rotate on single arrays, will transform *list into **list
void rot_word(unsigned char *list, int length, signed int spots) {
    unsigned char *proxy[length];

    for(int i = 0; i < length; i++) proxy[i] = &list[i];
    
    _rotate(proxy, length, spots);
}

//pos = left-shift, neg = right-shift
void _rotate(unsigned char **list, int length, signed int spots) {
  
  while (spots != 0){
    int shift = (spots < 0) ? -1 : 1;

    // Starting point:
    // - left-shift = list[1]
    // - right-shift = list[3] 
    int offset = (length + shift);
    unsigned char temp = *list[offset % length];

    // Loop through 0, 1, 2 because 3 will receive temp 
    for(int i = 0; i < (length-1); i++){
      // reverses the loop if shift is right
      int idx = offset + (i*shift);

      // Shifts an index to the left (+1) or right (-1) depending on shift
      *list[idx % length] = *list[(idx + shift) % length];
    }

    // (starting-point - shift) will receive temp  
    *list[(offset - shift) % length] = temp;
    spots -= shift;
  }
}

// Get rows first, then rotate rows
void shift_rows(unsigned char *block) {
  unsigned char *row[BLOCK_ROW];
      
  for (int r = 0; r < BLOCK_ROW; r++) {
    // Convert columns to rows
    for(int c = 0; c < BLOCK_COL; c++) row[c] = &block[r + (c * BLOCK_COL)];

    _rotate(row, BLOCK_ROW, r);
  } 
}

void invert_shift_rows(unsigned char *block) {
  unsigned char *row[BLOCK_ROW];
      
  for (int r = 0; r < BLOCK_ROW; r++) {
    // Convert columns to rows
    for(int c = 0; c < BLOCK_COL; c++) row[c] = &block[r + (c * BLOCK_COL)];

    _rotate(row, BLOCK_ROW, -r);
  } 
}