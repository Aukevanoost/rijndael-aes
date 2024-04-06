import ctypes
from util.lib import aes, format_word, format_block_hor
import aes_ref.aes as ref

#
# Here the roundKey will be XOR'ed in the current block
#
class TestAddRoundkey:

    def test_add_roundkey_first_block(self):
        input = ctypes.create_string_buffer(
            b'\x04\x66\x81\xe5' + 
            b'\xe0\xcb\x19\x9a' + 
            b'\x48\xf8\xd3\x7a' + 
            b'\x28\x06\x26\x4c'
        , 16)

        round_key = ctypes.create_string_buffer(
            b'\xa0\xfa\xfe\x17' + 
            b'\x88\x54\x2c\xb1' + 
            b'\x23\xa3\x39\x39' + 
            b'\x2a\x6c\x76\x05'
        , 16)
        
        expected  = b'\xa4\x9c\x7f\xf2' + \
                    b'\x68\x9f\x35\x2b' + \
                    b'\x6b\x5b\xea\x43' + \
                    b'\x02\x6a\x50\x49'

        # Act 
        aes.add_round_key(input, round_key)
        actual = ctypes.string_at(input, 16)

        # Assert
        assert actual.hex() == expected.hex()

    def test_add_roundkey_second_block(self):
        input = ctypes.create_string_buffer(
            b'\x58\x4d\xca\xf1' + 
            b'\x1b\x4b\x5a\xac' + 
            b'\xdb\xe7\xca\xa8' + 
            b'\x1b\x6b\xb0\xe5'
        , 16)

        round_key = ctypes.create_string_buffer(
            b'\xf2\xc2\x95\xf2' + 
            b'\x7a\x96\xb9\x43' + 
            b'\x59\x35\x80\x7a' + 
            b'\x73\x59\xf6\x7f'
        , 16)
        
        expected  = b'\xaa\x8f\x5f\x03' + \
                    b'\x61\xdd\xe3\xef' + \
                    b'\x82\xd2\x4a\xd2' + \
                    b'\x68\x32\x46\x9a'

        # Act 
        aes.add_round_key(input, round_key)
        actual = ctypes.string_at(input, 16)
        # print(format_block_hor(actual, 4))
        # print("")
        # print(format_block_hor(expected, 4))

        # Assert
        assert actual.hex() == expected.hex()

    def test_add_roundkey_first_block_against_ref(self):
        input = b'\x04\x66\x81\xe5' + \
                b'\xe0\xcb\x19\x9a' + \
                b'\x48\xf8\xd3\x7a' + \
                b'\x28\x06\x26\x4c'
        input_block = ctypes.create_string_buffer(input, 16)
        input_matrix_ref = ref.bytes2matrix(input)

        round_key = b'\xa0\xfa\xfe\x17' + \
                    b'\x88\x54\x2c\xb1' + \
                    b'\x23\xa3\x39\x39' + \
                    b'\x2a\x6c\x76\x05'
        
        input_key = ctypes.create_string_buffer(round_key, 16)
        input_key_matrix_ref = ref.bytes2matrix(round_key)

        # Act 
        aes.add_round_key(input_block, input_key)
        actual = ctypes.string_at(input_block, 16)

        ref.add_round_key(input_matrix_ref, input_key_matrix_ref)
        expected = ref.matrix2bytes(input_matrix_ref)

        # Assert
        # print(format_block_hor(actual, 4))
        # print("")
        # print(format_block_hor(expected, 4))
        assert actual.hex() == expected.hex()


    