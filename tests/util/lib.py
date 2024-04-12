import ctypes

aes = ctypes.CDLL("./dist/rijndael.so")

# Help python understand the return types of the functions
aes.expand_key.restype = ctypes.POINTER(ctypes.c_char * 176)
aes.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_char * 16)
aes.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_char * 16)