import ctypes
import random
from util.lib import aes, format_block_hor
import aes_ref.aes as ref
from wrappers.heaparray import HeapArray

class TestRandomInput:

    def _setup(self,block_size):
        return (
            bytes([random.randint(0, 255) for _ in range(block_size)]),
            bytes([random.randint(0, 255) for _ in range(block_size)]),
        )

    def test_aes_encrypt_against_ref(self):
        
        for _ in range(4):    
            # Arrange   
            (plaintext, key) = self._setup(16)

            # Act 
            actual = HeapArray.of(
                size=16, 
                fn=lambda: aes.aes_encrypt_block(
                    ctypes.create_string_buffer(plaintext, 16), 
                    ctypes.create_string_buffer(key, 16)
                )
            )       
            expected = ref.AES(key).encrypt_block(plaintext)

            # Assert
            assert actual.value == expected

        
    def test_aes_decrypt_against_ref(self):
        
        for _ in range(4):    
            # Arrange   
            (plaintext, key) = self._setup(16)

            # Act 
            actual = HeapArray.of(
                size=16, 
                fn=lambda: aes.aes_decrypt_block(
                    ctypes.create_string_buffer(plaintext, 16), 
                    ctypes.create_string_buffer(key, 16)
                )
            )       
            expected = ref.AES(key).decrypt_block(plaintext)

            # Assert
            assert actual.value == expected

    
    def test_aes_encrypt_and_decrypt(self):
        assertions =  []

        for _ in range(4):    
            (plaintext, key) = self._setup(16)

            encrypted = HeapArray.of(
                size=16, 
                fn=lambda: aes.aes_encrypt_block(
                    ctypes.create_string_buffer(plaintext, 16), 
                    ctypes.create_string_buffer(key, 16)
                )
            )       

            assertions.append((key, plaintext, encrypted.value))

        for rnd in range(len(assertions)):    
            (key, plaintext, cipher) = assertions[rnd]
            expected = plaintext

            actual = HeapArray.of(
                size=16, 
                fn=lambda: aes.aes_decrypt_block(
                    ctypes.create_string_buffer(cipher, 16), 
                    ctypes.create_string_buffer(key, 16)
                )
            )

            assert actual.value == expected

