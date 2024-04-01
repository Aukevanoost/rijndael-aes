import ctypes
from util.lib import aes, format_word
import aes_ref.aes as ref
import copy
from wrappers import UnitFixture

class TestEncryptMixColumns: 
     
    def test_column(self):
        # Arrange
        input = b'\x33\x55\x77\x99'
        expected = bytearray(list(input))
        word = copy.deepcopy(input)

        # Act
        ref.mix_single_column(expected)
        aes._mix_column(word, 4)
        actual = ctypes.string_at(word, 4)

        # Assert
        assert expected.hex() == actual.hex()

    def test_mixcolumns_rijndael_block(self):
        # The four numbers of one column are modulo multiplied in Rijndael's Galois Field by a given matrix.

        # Note, the matrix is inversed, cols are rows 
        fixture = UnitFixture(
                input = b'\xd4\xbf\x5d\x30' +
                        b'\xe0\xb4\x52\xae' +
                        b'\xb8\x41\x11\xf1' +
                        b'\x1e\x27\x98\xe5',
                        
             expected = b'\x04\x66\x81\xe5' +
                        b'\xe0\xcb\x19\x9a' +
                        b'\x48\xf8\xd3\x7a' + 
                        b'\x28\x06\x26\x4c',
        )

        block = ctypes.create_string_buffer(fixture.input, 16)

        # Act 
        aes.mix_columns(block)
        actual = ctypes.string_at(block, 16)

        # Assert
        assert actual.hex() == fixture.expected.hex()

    def test_mixcolumns(self):
        # The four numbers of one column are modulo multiplied in Rijndael's Galois Field by a given matrix.

        input = b'\xd4\xe0\xb8\x1e'+\
                b'\xbf\xb4\x41\x27'+\
                b'\x5d\x52\x11\x98'+\
                b'\x30\xae\xf1\xe5' 
        
        #print(format_word(input))

        expected = ref.bytes2matrix(input)
        word = copy.deepcopy(input)
        
        # Act
        ref.mix_columns(expected)
        aes.mix_columns(word)
        actual = ctypes.string_at(word, 16)

        # Assert
        printable = ref.matrix2bytes(expected)
        print(format_word(printable))
        print(format_word(actual))

        assert printable.hex() == actual.hex()

class TestDecryptMixColumns: 
    def test_mixcolumns_rijndael_block(self):
        # The four numbers of one column are modulo multiplied in Rijndael's Galois Field by a given matrix.

        fixture = UnitFixture(                             
                input = b'\x04\x66\x81\xe5' +
                        b'\xe0\xcb\x19\x9a' +
                        b'\x48\xf8\xd3\x7a' + 
                        b'\x28\x06\x26\x4c',

             expected = b'\xd4\xbf\x5d\x30' +
                        b'\xe0\xb4\x52\xae' +
                        b'\xb8\x41\x11\xf1' +
                        b'\x1e\x27\x98\xe5'
        )

        block = ctypes.create_string_buffer(fixture.input, 16)

        # Act 
        aes.invert_mix_columns(block)
        actual = ctypes.string_at(block, 16)

        # Assert
        assert actual.hex() == fixture.expected.hex()

    def test_mixcolumns(self):
        # The four numbers of one column are modulo multiplied in Rijndael's Galois Field by a given matrix.

        input = b'\x04\x66\x81\xe5' + \
                b'\xe0\xcb\x19\x9a' + \
                b'\x48\xf8\xd3\x7a' + \
                b'\x28\x06\x26\x4c'
        
        #print(format_word(input))

        expected = ref.bytes2matrix(input)
        word = copy.deepcopy(input)
        
        # Act
        ref.inv_mix_columns(expected)
        aes.invert_mix_columns(word)
        actual = ctypes.string_at(word, 16)

        # Assert
        printable = ref.matrix2bytes(expected)
        # print(format_word(printable))
        # print(format_word(actual))

        assert printable.hex() == actual.hex()