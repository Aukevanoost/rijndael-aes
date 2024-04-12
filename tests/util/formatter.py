
class Formatter:
    def __init__(self, row_size, col_size):
        self._row_size = row_size
        self._col_size = col_size
        self._block_size = row_size*col_size

    # Format 'word' to: 01:02:03
    def word(self, word):
        return ':'.join([word.hex()[i:i+2] for i in range(0, len(word)*2, 2)])
        
    # Format 'blocks' to: (so note, col and row inverted)
    #   01:02:03
    #   04:05:06
    #   07:08:09
    # 
    #   01:02:03
    #   04:05:06
    #   07:08:09
    def block_vert(self, a):
        input = a.hex()
        output = ''
        for i in range(0, len(a)):
            output += input[i*2] + input[i*2+1]
            output += '\n' if ((i+1) % self._col_size == 0) else ':'
            if ((i+1) % self._block_size == 0): output += '\n'   

        return output   

    # Format 'blocks' to: 
    #   01:04:07  01:04:07
    #   02:05:08  02:05:08
    #   03:06:09  03:06:09
    def block_hor(self, a):
        input = a.hex()
        output = ['' for _ in range(self._col_size)]
        for cell_idx in range(0, len(a)):
            byte_idx = cell_idx*2
            output[cell_idx % self._col_size] += input[byte_idx] + input[byte_idx+1]

            output[cell_idx % self._col_size] += '  ' if (( (cell_idx // self._col_size) + 1) % self._row_size == 0) else ':'

        return '\n'.join(output)

    # Flattens 'matrix' to single dimensional byte[]
    def ref_key(self, matrices):
        output = bytes(sum(matrices[0], []))
        
        for i in range(1, len(matrices)):
            for j in range(self._col_size):
                output += matrices[i][j]

        return output
    
    @staticmethod
    def of_block(size):
        return Formatter(size, size)
