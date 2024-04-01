import ctypes

aes = ctypes.CDLL("./dist/rijndael.so")

aes.expand_key.restype = ctypes.POINTER(ctypes.c_char * 16)

def format_word(a):
    return ':'.join([a.hex()[i:i+2] for i in range(0, len(a)*2, 2)])
    

def format_block_vert(a):
    input = a.hex()
    output = ''
    for i in range(0, len(a)):
        output += input[i*2] + input[i*2+1]
        output += '\n' if ((i+1)%4 == 0) else ':'
        if ((i+1)%16 == 0): output += '\n'   

    return output
    

def format_block_hor(a, rows):
    input = a.hex()
    output = ['' for _ in range(rows)]
    for i in range(0, len(a)):
        idx = i*2
        output[i%rows] += input[idx] + input[idx+1]
        output[i%rows] += '  ' if (((i // rows)+1)%4 == 0) else ':'

    return '\n'.join(output)

def format_ref_key(matrices):
    output = bytes(sum(matrices[0], []))
    
    for i in range(1, len(matrices)):
        for j in range(4):
            output += matrices[i][j]

    return output
