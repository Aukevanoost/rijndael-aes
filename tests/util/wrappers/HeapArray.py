import ctypes
from util.lib import aes

#
# HeapArray: A wrapper around a pointer to prevent memory leaks
#
class HeapArray:
    def __init__(self, size, addr):
        self._active = True
        self._addr = addr
        self._size = size

    @property
    def value(self): 
         return ctypes.string_at(self._addr, self._size) 

    def hex(self):
        return self.value.hex()

    def free(self):
        if self._active:
            self._active = False
            aes.cleanup(self._addr)

    def __del__(self):
        self.free()

    @staticmethod
    def set(size, addr):
        return HeapArray(size, addr)
    
    @staticmethod
    def of(size, fn):
        return HeapArray(size, fn())
