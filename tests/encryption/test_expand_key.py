import ctypes
from util.lib import aes, pretty_hex, pretty_blocks
import aes_ref.aes as ref
import copy
from wrappers import UnitFixture

class TestExpandKey: 
    def test_expand_key(self):
        # Arrange
        input = b'\x00\x01\x02\x03' + \
                b'\x10\x11\x12\x13' + \
                b'\x20\x21\x22\x23' + \
                b'\x30\x31\x32\x33'   \

        master_key = ctypes.create_string_buffer(input, 16)
        # expected = b"\x0b" * 16

        # Act
        address = aes.expand_key(master_key)
        actual = ctypes.string_at(address, 176)
        print(pretty_blocks(actual))
        # Assert
        assert 1 == 0
        aes.cleanup(address)

# def test_xor():
#     prev_row = b"\xaa" * 4
#     # Arrange
#     word = ctypes.create_string_buffer(b"\x00\xa9\xc4\xff", 4)
#     expected = b"\x63\x7C\x77\x7B"

#     print(b'\x00')
#     # Act 
#     aes.subbytes(word)
#     actual = ctypes.string_at(word, 4)

#     assert actual == expected
