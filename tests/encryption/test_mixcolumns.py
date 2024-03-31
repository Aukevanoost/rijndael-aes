import ctypes
from util.lib import aes
import aes_ref.aes as ref
import copy

class TestEncryptMixColumns: 
     
    def test_word(self):
        # Arrange
        input = b'\x33\x55\x77\x99'
        expected = bytearray(list(input))
        word = copy.deepcopy(input)

        # Act
        ref.mix_single_column(expected)
        aes._mix_word(word)
        actual = ctypes.string_at(word, 4)

        # Assert
        assert expected.hex() == actual.hex()
