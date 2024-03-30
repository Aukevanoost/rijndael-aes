import ctypes
from util.lib import aes
from wrappers import UnitFixture

class TestWordSubBytesLogic: 
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

    def test_subbytes_row_overflow(self):
        # Arrange
        S_BOX = b'\x00' * 16 + b'\xaa\xbb\xcc\xdd'
        fixture = UnitFixture(
                input = b'\x10\x11\x12\x13',
             expected = b'\xaa\xbb\xcc\xdd',
        )
        word = ctypes.create_string_buffer(fixture.input, 4)

        # Act
        aes._sub_word(word, S_BOX)
        actual = ctypes.string_at(word, 4)

        # Assert
        assert actual.hex() == fixture.expected.hex()

    def test_subbytes_column(self):
        # Arrange
        S_BOX = b'\x99' * 16 + b'\xaa' * 16 + b'\xbb' * 16 + b'\xcc' * 16 + b'\xdd' * 16
        fixture = UnitFixture(
                input = b'\x10\x20\x30\x40',
             expected = b'\xaa\xbb\xcc\xdd',
        )
        word = ctypes.create_string_buffer(fixture.input, 4)

        # Act
        aes._sub_word(word, S_BOX)
        actual = ctypes.string_at(word, 4)

        # Assert
        assert actual.hex() == fixture.expected.hex()

class TestEncryptSubBytes:
    def test_sbox_first_block(self):
        fixture = UnitFixture(
                input = b'\x00\x01\x02\x03' +
                        b'\x10\x11\x12\x13' +
                        b'\x20\x21\x22\x23' +
                        b'\x30\x31\x32\x33',

             expected = b'\x63\x7C\x77\x7B' +
                        b'\xCA\x82\xC9\x7D' +
                        b'\xB7\xFD\x93\x26' +
                        b'\x04\xC7\x23\xC3'
            )

        block = ctypes.create_string_buffer(fixture.input, 16)

        # Act 
        aes.sub_bytes(block)
        actual = ctypes.string_at(block, 16)

        # Assert
        assert actual.hex() == fixture.expected.hex()

    def test_sbox_last_block(self):
        fixture = UnitFixture(
                input = b'' +
                        b'\xcc\xcd\xce\xcf' +
                        b'\xdc\xdd\xde\xdf' +
                        b'\xec\xed\xee\xef' +
                        b'\xfc\xfd\xfe\xff',

             expected = b'\x4B\xBD\x8B\x8A' +
                        b'\x86\xC1\x1D\x9E' +
                        b'\xCE\x55\x28\xDF' +
                        b'\xB0\x54\xBB\x16'
            )

        block = ctypes.create_string_buffer(fixture.input, 16)

        # Act 
        aes.sub_bytes(block)
        actual = ctypes.string_at(block, 16)

        # Assert
        assert actual.hex() == fixture.expected.hex()

    def test_sbox_rijndael_block(self):
        fixture = UnitFixture(
                input = b'\x19\xa0\x9a\xe9' +
                        b'\x3d\xf4\xc6\xf8' +
                        b'\xe3\xe2\x8d\x48' +
                        b'\xbe\x2b\x2a\x08',

             expected = b'\xd4\xe0\xb8\x1e' +
                        b'\x27\xbf\xb4\x41' +
                        b'\x11\x98\x5d\x52' +
                        b'\xae\xf1\xe5\x30',
        )

        block = ctypes.create_string_buffer(fixture.input, 16)

        # Act 
        aes.sub_bytes(block)
        actual = ctypes.string_at(block, 16)

        # Assert
        assert actual.hex() == fixture.expected.hex()

class TestDecryptSubBytes:
    def test_sbox_inv_first_block(self):
        fixture = UnitFixture(
                input = b'\x00\x01\x02\x03' +
                        b'\x10\x11\x12\x13' +
                        b'\x20\x21\x22\x23' +
                        b'\x30\x31\x32\x33',

             expected = b'\x52\x09\x6A\xD5' +
                        b'\x7C\xE3\x39\x82' +
                        b'\x54\x7B\x94\x32' +
                        b'\x08\x2E\xA1\x66'
            )

        block = ctypes.create_string_buffer(fixture.input, 16)

        # Act 
        aes.invert_sub_bytes(block)
        actual = ctypes.string_at(block, 16)

        # Assert
        assert actual.hex() == fixture.expected.hex()

    def test_sbox_inv_last_block(self):
        fixture = UnitFixture(
                input = b'' +
                        b'\xcc\xcd\xce\xcf' +
                        b'\xdc\xdd\xde\xdf' +
                        b'\xec\xed\xee\xef' +
                        b'\xfc\xfd\xfe\xff',

             expected = b'\x27\x80\xEC\x5F' +
                        b'\x93\xC9\x9C\xEF' +
                        b'\x83\x53\x99\x61' +
                        b'\x55\x21\x0C\x7D'
            )

        block = ctypes.create_string_buffer(fixture.input, 16)

        # Act 
        aes.invert_sub_bytes(block)
        actual = ctypes.string_at(block, 16)

        # Assert
        assert actual.hex() == fixture.expected.hex()

    def test_sbox_inv_rijndael_block(self):
        fixture = UnitFixture(
                input = b'\xd4\xe0\xb8\x1e' +
                        b'\x27\xbf\xb4\x41' +
                        b'\x11\x98\x5d\x52' +
                        b'\xae\xf1\xe5\x30',
                        
             expected = b'\x19\xa0\x9a\xe9' +
                        b'\x3d\xf4\xc6\xf8' +
                        b'\xe3\xe2\x8d\x48' +
                        b'\xbe\x2b\x2a\x08',
        )

        block = ctypes.create_string_buffer(fixture.input, 16)

        # Act 
        aes.invert_sub_bytes(block)
        actual = ctypes.string_at(block, 16)

        # Assert
        assert actual.hex() == fixture.expected.hex()