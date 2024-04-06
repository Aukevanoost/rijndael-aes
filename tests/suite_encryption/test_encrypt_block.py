import ctypes
from util.lib import aes, format_ref_key, format_block_hor
import aes_ref.aes as ref
from wrappers.heaparray import HeapArray


class TestEncryptBlock:

    def test_encrypt_block(self):
        input = ctypes.create_string_buffer(
            b'\x32\x43\xf6\xa8' + 
            b'\x88\x5a\x30\x8d' + 
            b'\x31\x31\x98\xa2' + 
            b'\xe0\x37\x07\x34'
        , 16)

        round_key = ctypes.create_string_buffer(
            b'\x2b\x7e\x15\x16' + 
            b'\x28\xae\xd2\xa6' + 
            b'\xab\xf7\x15\x88' + 
            b'\x09\xcf\x4f\x3c'
        , 16)

        expected  = b'\x39\x25\x84\x1d' + \
                    b'\x02\xdc\x09\xfb' + \
                    b'\xdc\x11\x85\x97' + \
                    b'\x19\x6a\x0b\x32'

        # Act 
        actual = HeapArray.of(
            size=16, 
            fn=lambda: aes.aes_encrypt_block(input, round_key)
        )        

        # Assert
        print(format_block_hor(actual.value, 4))
        assert actual.value == expected

    
    def test_encrypt_block_with_ref(self):
        message =   b'\x32\x43\xf6\xa8' + \
                    b'\x88\x5a\x30\x8d' + \
                    b'\x31\x31\x98\xa2' + \
                    b'\xe0\x37\x07\x34'
        message_input = ctypes.create_string_buffer(message, 16)


        round_key = b'\x2b\x7e\x15\x16' + \
                    b'\x28\xae\xd2\xa6' + \
                    b'\xab\xf7\x15\x88' + \
                    b'\x09\xcf\x4f\x3c'
        round_key_input = ctypes.create_string_buffer(round_key, 16)
        
        # Act 
        actual = HeapArray.of(
            size=16, 
            fn=lambda: aes.aes_encrypt_block(message_input, round_key_input)
        )       
        expected = ref.AES(round_key).encrypt_block(message)
 

        # Assert
        # print(format_block_hor(actual.value, 4))
        # print(format_block_hor(expected, 4))
        assert actual.value == expected

    
    def test_encrypt_block_multiple_times(self):
        msg = [
            'aanbouwkeukentje',
            'aandelenmakelaar',
            'afvoermiddeltjes',
            'zuurstoftekorten'
        ]
        keys = [
            'TZm58r8si7h39kYV',
            'vFijZrNLn9uQST3i',
            'Z1PwIcqJprZMeEsy',
            'al0iXZhNrdhhMI3X'
        ]
        for rnd in range(len(msg)):       


            # Act 
            actual = HeapArray.of(
                size=16, 
                fn=lambda: aes.aes_encrypt_block(
                    ctypes.create_string_buffer(bytes(msg[rnd], 'ascii'), 16), 
                    ctypes.create_string_buffer(bytes(keys[rnd], 'ascii'), 16)
                )
            )       
            expected = ref.AES(bytes(keys[rnd], 'ascii')).encrypt_block(bytes(msg[rnd], 'ascii'))
            # Assert
            assert actual.value == expected
