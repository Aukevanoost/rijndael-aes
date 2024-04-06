import ctypes
from util.lib import aes

#
# A will be XOR'ed into B
# example:
# - XORB(00001111, 00110011) = 00110011
#
class TestXORBLogic: 
    def test_xor_single_pos(self):
        # Arrange
        a = ctypes.create_string_buffer(b'\xFF', 1)
        b = ctypes.create_string_buffer(b'\x00', 1)
        expected = b'\xFF'

        # Act
        aes._XOR_B(a, b, 1)
        actual = ctypes.string_at(b, 1)

        # Assert
        assert actual == expected

    def test_xor_single_neg(self):
        # Arrange
        a = ctypes.create_string_buffer(b'\xFF', 1)
        b = ctypes.create_string_buffer(b'\xFF', 1)
        expected = b'\x00'

        # Act
        aes._XOR_B(a, b, 1)
        actual = ctypes.string_at(b, 1)

        # Assert
        assert actual == expected

    def test_xor_word(self):
        # Arrange
        a = ctypes.create_string_buffer(b'\xAA\xF0\xCC\xE7', 4) # 10101010 11110000 11001100 11100111
        b = ctypes.create_string_buffer(b'\x0F\xE7\xAA\x18', 4) # 00001111 11100111 10101010 00011000
        expected = b'\xA5\x17\x66\xFF'                          # 10100101 00010111 01100110 11111111

        # Act
        aes._XOR_B(a, b, 4)
        actual = ctypes.string_at(b, 4)

        # Assert
        assert actual == expected
