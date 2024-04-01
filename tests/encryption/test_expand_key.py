import ctypes
from util.lib import aes, format_ref_key, format_block_hor
import aes_ref.aes as ref

# Example used: 
# https://formaestudio.com/rijndaelinspector/archivos/Rijndael_Animation_v4_eng-html5.html
class TestExpandKey: 
    def test_expand_key(self):
        # # Arrange
        input = b'\x2b\x7e\x15\x16' + \
                b'\x28\xae\xd2\xa6' + \
                b'\xab\xf7\x15\x88' + \
                b'\x09\xcf\x4f\x3c'   \
                
        master_key = ctypes.create_string_buffer(input, 16)

        expected =  b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c' + \
                    b'\xa0\xfa\xfe\x17\x88\x54\x2c\xb1\x23\xa3\x39\x39\x2a\x6c\x76\x05' + \
                    b'\xf2\xc2\x95\xf2\x7a\x96\xb9\x43\x59\x35\x80\x7a\x73\x59\xf6\x7f' + \
                    b'\x3d\x80\x47\x7d\x47\x16\xfe\x3e\x1e\x23\x7e\x44\x6d\x7a\x88\x3b' + \
                    b'\xef\x44\xa5\x41\xa8\x52\x5b\x7f\xb6\x71\x25\x3b\xdb\x0b\xad\x00' + \
                    b'\xd4\xd1\xc6\xf8\x7c\x83\x9d\x87\xca\xf2\xb8\xbc\x11\xf9\x15\xbc' + \
                    b'\x6d\x88\xa3\x7a\x11\x0b\x3e\xfd\xdb\xf9\x86\x41\xca\x00\x93\xfd' + \
                    b'\x4e\x54\xf7\x0e\x5f\x5f\xc9\xf3\x84\xa6\x4f\xb2\x4e\xa6\xdc\x4f' + \
                    b'\xea\xd2\x73\x21\xb5\x8d\xba\xd2\x31\x2b\xf5\x60\x7f\x8d\x29\x2f' + \
                    b'\xac\x77\x66\xf3\x19\xfa\xdc\x21\x28\xd1\x29\x41\x57\x5c\x00\x6e' + \
                    b'\xd0\x14\xf9\xa8\xc9\xee\x25\x89\xe1\x3f\x0c\xc8\xb6\x63\x0c\xa6'

        # Act
        address = aes.expand_key(master_key)
        actual = ctypes.string_at(address, 176)

        # Assert
        # print(format_block_hor(actual, 4))
        # print("")
        # print(format_block_hor(expected, 4))
        aes.cleanup(address)
        assert actual == expected

    def test_expand_key_from_ref(self):
        # Arrange
        input = b'\x2b\x7e\x15\x16' + \
                b'\x28\xae\xd2\xa6' + \
                b'\xab\xf7\x15\x88' + \
                b'\x09\xcf\x4f\x3c'   \
                
        master_key = ctypes.create_string_buffer(input, 16)

        # # Act
        address = aes.expand_key(master_key)
        actual = ctypes.string_at(address, 176)
        expected = format_ref_key(ref.AES(input)._key_matrices)

        # Assert
        # print(format_block_hor(actual, 4))
        # print("")
        # print(format_block_hor(expected, 4))
        aes.cleanup(address)
        assert expected == actual