import ctypes
from util.lib import aes



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



# def test_expand_key():
#     # Arrange
#     master_key = ctypes.create_string_buffer(b"\x0b" * 16, 16)
#     expected = b"\x0b" * 16

#     # Act
#     address = aes.expand_key(master_key)
#     actual = ctypes.string_at(address, 16)

#     # Assert
#     assert actual == expected
#     aes.cleanup(address)
