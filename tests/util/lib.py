import ctypes

aes = ctypes.CDLL("./dist/rijndael.so")

aes.expand_key.restype = ctypes.POINTER(ctypes.c_char * 16)

def pretty_hex(a):
    print(':'.join([a.hex()[i:i+2] for i in range(0, len(a)*2, 2)]))
