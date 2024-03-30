import ctypes

aes = ctypes.CDLL("./dist/rijndael.so")

aes.expand_key.restype = ctypes.POINTER(ctypes.c_char * 16)
