import ctypes
from util.lib import aes
from wrappers import UnitFixture

class TestEncryptSubBytes:
    def test_subbytes_word(self):
        # Arrange
        S_BOX = b'\x11\x22\x33\x44'
        fixture = UnitFixture(
                input = b'\x00\x01\x02\x03',
             expected = b'\x11\x22\x33\x44',
        )
        word = ctypes.create_string_buffer(fixture.input, 4)

        # Act
        aes._sub_word(word, S_BOX)
        actual = ctypes.string_at(word, 4)

        # Assert
        assert actual.hex() == fixture.expected.hex()

    #     actual = ctypes.string_at(block, 16)
    # def test_subbytes_rijndael_block(self):
    #     fixture = UnitFixture(
    #             input = b'\x19\xa0\x9a\xe9' +
    #                     b'\x3d\xf4\xc6\xf8' +
    #                     b'\xe3\xe2\x8d\x48' +
    #                     b'\xbe\x2b\x2a\x08',

    #          expected = b'\x19\xa0\x9a\xe9' +
    #                     b'\x3d\xf4\xc6\xf8' +
    #                     b'\xe3\xe2\x8d\x48' +
    #                     b'\xbe\x2b\x2a\x08',
    #     )

    #     block = ctypes.create_string_buffer(fixture.input, 16)

    #     # Act 
    #     aes.sub_bytes(block)
    #     actual = ctypes.string_at(block, 16)

    #     # Assert
    #     assert actual == fixture.expected