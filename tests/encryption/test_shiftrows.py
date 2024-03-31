import ctypes
from util.lib import aes, pretty_hex
from wrappers import UnitFixture
import aes_ref.aes as ref


class TestEncryptShiftRows:
    # 
    # DEFAULT SCENARIO: ROTATING A SINGLE WORD
    # 
    def test_word_rotate(self):
        fixtures = [
            UnitFixture(input=b"\x00\x01\x02\x03", expected=b"\x01\x02\x03\x00"),
            UnitFixture(input=b"\x01\x02\x03\x04", expected=b"\x02\x03\x04\x01"),
            UnitFixture(input=b"\xaa\xbb\xcc\xdd", expected=b"\xbb\xcc\xdd\xaa"),
            UnitFixture(input=b"\x37\x36\x35\x34", expected=b"\x36\x35\x34\x37"),
        ]
        
        for rot in fixtures:
            # Arrange
            word = ctypes.create_string_buffer(rot.input, 4)

            # Act 
            aes.shift_word(word, 4)
            actual = ctypes.string_at(word, 4)

            # Assert
            assert actual.hex() == rot.expected.hex()
            
    # 
    # Test multiple rotations
    # 
    def test_word_rotate_thrice(self):
        # Arrange
        fixture = UnitFixture(input=b"\x00\x01\x02\x03", expected=b"\x03\x00\x01\x02")
        word = ctypes.create_string_buffer(fixture.input, 4)

        # Act 
        aes.shift_word(word, 4)
        aes.shift_word(word, 4)
        aes.shift_word(word, 4)
        actual = ctypes.string_at(word, 4)

        # Assert
        assert actual.hex() == fixture.expected.hex()
        
    # 
    # Test shiftrows block
    # 
    def test_shiftrows_block(self):
        fixture = UnitFixture(
                input = b'\x11\x21\x31\x41' +
                        b'\x12\x22\x32\x42' +
                        b'\x13\x23\x33\x43' +
                        b'\x14\x24\x34\x44',

             expected = b'\x11\x22\x33\x44' +
                        b'\x12\x23\x34\x41' +
                        b'\x13\x24\x31\x42' +
                        b'\x14\x21\x32\x43'
        )

        block = ctypes.create_string_buffer(fixture.input, 16)

        # Act 
        aes.shift_rows(block)
        actual = ctypes.string_at(block, 16)

        # Assert
        print('i: ' + pretty_hex(fixture.input))
        print('e: ' + pretty_hex(fixture.expected))
        print('a: ' + pretty_hex(actual))
        assert actual == fixture.expected

    # 
    # Test a real block
    # src: https://formaestudio.com/rijndaelinspector/archivos/Rijndael_Animation_v4_eng-html5.html
    def test_shiftrows_rijndael_block(self):
        fixture = UnitFixture(

                input = b'\xd4\x27\x11\xae' + # Col 1
                        b'\xe0\xbf\x98\xf1' + # Col 2
                        b'\xb8\xb4\x5d\xe5' + # Col 3
                        b'\x1e\x41\x52\x30',  # Col 4

            expected =  b'\xd4\xbf\x5d\x30' +
                        b'\xe0\xb4\x52\xae' + 
                        b'\xb8\x41\x11\xf1' +
                        b'\x1e\x27\x98\xe5',  
        )

        block = ctypes.create_string_buffer(fixture.input, 16)

        # Act 
        aes.shift_rows(block)
        actual = ctypes.string_at(block, 16)

        # Assert
        assert actual == fixture.expected

    def test_shiftrows_against_ref(self):
        input = b'\xd4\xe0\xb8\x1e' + \
                b'\x27\xbf\xb4\x41' + \
                b'\x11\x98\x5d\x52' + \
                b'\xae\xf1\xe5\x30'
        
        ref_byte_matrix = ref.bytes2matrix(input)
        block = ctypes.create_string_buffer(input, 16)

        # Act 
        ref.shift_rows(ref_byte_matrix)
        aes.shift_rows(block)

        actual = ctypes.string_at(block, 16)
        expected = ref.matrix2bytes(ref_byte_matrix)

        # Assert
        assert actual.hex() == expected.hex()



class TestDecryptShiftRows:
# 
    # DEFAULT SCENARIO: ROTATING A SINGLE LIST
    # 
    def test_word_rotate(self):
        for rot in [
            UnitFixture(input=b"\x00\x01\x02\x03", expected=b"\x03\x00\x01\x02"),
            UnitFixture(input=b"\x01\x02\x03\x04", expected=b"\x04\x01\x02\x03"),
            UnitFixture(input=b"\xaa\xbb\xcc\xdd", expected=b"\xdd\xaa\xbb\xcc"),
            UnitFixture(input=b"\x37\x36\x35\x34", expected=b"\x34\x37\x36\x35"),
        ]:
            # Arrange
            word = ctypes.create_string_buffer(rot.input, 4)

            # Act 
            aes.invert_shift_word(ctypes.pointer(word), 4)
            actual = ctypes.string_at(word, 4)

            # Assert
            assert actual.hex() == rot.expected.hex()

    # 
    # Test multiple rotations
    # 
    def test_word_rotate_thrice(self):
        # Arrange
        fixture = UnitFixture(input=b"\x00\x01\x02\x03", expected=b"\x01\x02\x03\x00")
        word = ctypes.create_string_buffer(fixture.input, 4)

        # Act 
        aes.invert_shift_word(word, 4)
        aes.invert_shift_word(word, 4)
        aes.invert_shift_word(word, 4)
        actual = ctypes.string_at(word, 4)

        # Assert
        assert actual.hex() == fixture.expected.hex()

    def test_shiftrows_rijndael_block_decrypt(self):
        fixture = UnitFixture(
                input = b'\xd4\xbf\x5d\x30' +
                        b'\xe0\xb4\x52\xae' + 
                        b'\xb8\x41\x11\xf1' +
                        b'\x1e\x27\x98\xe5',  

            expected =  b'\xd4\x27\x11\xae' +
                        b'\xe0\xbf\x98\xf1' +
                        b'\xb8\xb4\x5d\xe5' + 
                        b'\x1e\x41\x52\x30', 
        )

        block = ctypes.create_string_buffer(fixture.input, 16)

        # Act 
        aes.invert_shift_rows(block)
        actual = ctypes.string_at(block, 16)

        # Assert
        assert actual.hex() == fixture.expected.hex()
        
    def test_shiftrows_decrypt_against_ref(self):
        input = b'\xd4\x27\x11\xae' + \
                b'\xe0\xbf\x98\xf1' + \
                b'\xb8\xb4\x5d\xe5' + \
                b'\x1e\x41\x52\x30'
        
        ref_byte_matrix = ref.bytes2matrix(input)
        block = ctypes.create_string_buffer(input, 16)

        # Act 
        ref.inv_shift_rows(ref_byte_matrix)
        aes.invert_shift_rows(block)

        actual = ctypes.string_at(block, 16)
        expected = ref.matrix2bytes(ref_byte_matrix)

        # Assert
        assert actual.hex() == expected.hex()
