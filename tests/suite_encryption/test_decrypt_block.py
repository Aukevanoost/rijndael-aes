import ctypes
from util.lib import aes, format_block_hor
import aes_ref.aes as ref
from wrappers.heaparray import HeapArray

class TestDecryptBlock:

    def test_decrypt_block(self):
        input = ctypes.create_string_buffer(
            b'\x39\x25\x84\x1d' + \
            b'\x02\xdc\x09\xfb' + \
            b'\xdc\x11\x85\x97' + \
            b'\x19\x6a\x0b\x32'
        , 16)

        round_key = ctypes.create_string_buffer(
            b'\x2b\x7e\x15\x16' + 
            b'\x28\xae\xd2\xa6' + 
            b'\xab\xf7\x15\x88' + 
            b'\x09\xcf\x4f\x3c'
        , 16)

        expected  = b'\x32\x43\xf6\xa8' + \
                    b'\x88\x5a\x30\x8d' + \
                    b'\x31\x31\x98\xa2' + \
                    b'\xe0\x37\x07\x34'

        # Act 
        actual = HeapArray.of(
            size=16, 
            fn=lambda: aes.aes_decrypt_block(input, round_key)
        )        

        # Assert
        # print(format_block_hor(actual.value, 4))
        assert actual.value == expected

    
    def test_encrypt_block_with_ref(self):
        cipher =    b'\x39\x25\x84\x1d' + \
                    b'\x02\xdc\x09\xfb' + \
                    b'\xdc\x11\x85\x97' + \
                    b'\x19\x6a\x0b\x32'
        cipher_input = ctypes.create_string_buffer(cipher, 16)


        round_key = b'\x2b\x7e\x15\x16' + \
                    b'\x28\xae\xd2\xa6' + \
                    b'\xab\xf7\x15\x88' + \
                    b'\x09\xcf\x4f\x3c'
        round_key_input = ctypes.create_string_buffer(round_key, 16)
        
        # Act 
        actual = HeapArray.of(
            size=16, 
            fn=lambda: aes.aes_decrypt_block(cipher_input, round_key_input)
        )       
        expected = ref.AES(round_key).decrypt_block(cipher)
 

        # Assert
        # print(format_block_hor(actual.value, 4))
        # print(format_block_hor(expected, 4))
        assert actual.value == expected

    def test_decrypt_block_multiple_times(self):
        cipher = [
            b'\x8d\x2b\x21\x1a\xe0\x7b\x6f\xb5\xbc\xa8\xfa\xa0\x2b\xb2\xa2\x0c',
            b'\xa2\x5e\x98\xc0\x5e\x8c\x98\xb8\x24\xba\x5a\x75\xcc\x65\x10\x2e',
            b'\xc6\xca\x04\xbd\xed\x1b\x21\x46\x2f\x59\x1d\x95\x2c\x9a\x11\x63',
            b'\xa8\xfa\x94\x6a\x53\xad\x28\x47\x6e\xa7\xbe\x08\xd7\x4e\x46\x5f'
        ]
        keys = [
            'TZm58r8si7h39kYV',
            'vFijZrNLn9uQST3i',
            'Z1PwIcqJprZMeEsy',
            'al0iXZhNrdhhMI3X'
        ]
        for rnd in range(len(cipher)):       


            # Act 
            actual = HeapArray.of(
                size=16, 
                fn=lambda: aes.aes_decrypt_block(
                    ctypes.create_string_buffer(cipher[rnd], 16), 
                    ctypes.create_string_buffer(bytes(keys[rnd], 'ascii'), 16)
                )
            )       
            expected = ref.AES(bytes(keys[rnd], 'ascii')).decrypt_block(cipher[rnd])
            # Assert
            # print(actual.value.decode('ascii'))
            assert actual.value == expected

    