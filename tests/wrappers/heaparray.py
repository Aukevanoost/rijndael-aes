
import ctypes
from util.lib import aes

class HeapArray:
    def __init__(self, size, addr):
        self.active = True
        self._addr = addr
        self._val = ctypes.string_at(addr, size)

    @property
    def value(self): 
         return self._val 

    def hex(self):
        return self._val.hex()

    def __del__(self):
        aes.cleanup(self._addr)

    @staticmethod
    def set(size, addr):
        return HeapArray(size, addr)
    
    @staticmethod
    def of(size, fn):
        return HeapArray(size, fn())
