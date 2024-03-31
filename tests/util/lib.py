import ctypes

aes = ctypes.CDLL("./dist/rijndael.so")

aes.expand_key.restype = ctypes.POINTER(ctypes.c_char * 16)

def pretty_hex(a):
    return ':'.join([a.hex()[i:i+2] for i in range(0, len(a)*2, 2)])

def pretty_blocks(a):
    input = a.hex()
    output = ''
    for i in range(0, len(a)):
        output += input[i*2] + input[i*2+1]
        output += '\n' if ((i+1)%4 == 0) else ':'
        if ((i+1)%16 == 0): output += '\n'   

    return output
