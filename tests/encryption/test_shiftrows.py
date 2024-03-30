import ctypes
from util.lib import aes
from wrappers import UnitFixture


class TestEncryptShiftRows:
    # 
    # DEFAULT SCENARIO: ROTATING A SINGLE WORD
    # 
    def test_rotword_right(self):
        for rot in [
            UnitFixture(input=b"\x00\x01\x02\x03", expected=b"\x03\x00\x01\x02"),
            UnitFixture(input=b"\x01\x02\x03\x04", expected=b"\x04\x01\x02\x03"),
            UnitFixture(input=b"\xaa\xbb\xcc\xdd", expected=b"\xdd\xaa\xbb\xcc"),
            UnitFixture(input=b"\x37\x36\x35\x34", expected=b"\x34\x37\x36\x35"),
        ]:
            # Arrange
            word = ctypes.create_string_buffer(rot.input, 4)

            # Act 
            aes._rot_word(word, -1)
            actual = ctypes.string_at(word, 4)

            # Assert
            assert actual == rot.expected

    # 
    # (POS) Test multiple rotations
    # 
    def test_rotword_zero(self):
        # Arrange
        fixture = UnitFixture(input=b"\x00\x01\x02\x03", expected=b"\x00\x01\x02\x03")
        word = ctypes.create_string_buffer(fixture.input, 4)

        # Act 
        aes._rot_word(word, 0)
        actual = ctypes.string_at(word, 4)

        # Assert
        assert actual == fixture.expected

    # 
    # (NEG) Test multiple rotations
    # 
    def test_rotword_right_twice(self):
        # Arrange
        fixture = UnitFixture(input=b"\x00\x01\x02\x03", expected=b"\x01\x02\x03\x00")
        word = ctypes.create_string_buffer(fixture.input, 4)

        # Act 
        aes._rot_word(word, -3)
        actual = ctypes.string_at(word, 4)

        # Assert
        assert actual == fixture.expected

    # 
    # Test multiple rotations
    # 
    def test_shiftrows_block(self):
        fixture = UnitFixture(
                input = b'\x01\x02\x03\x04' +
                        b'\x01\x02\x03\x04' +
                        b'\x01\x02\x03\x04' +
                        b'\x01\x02\x03\x04',

            expected = b'\x01\x02\x03\x04' +
                        b'\x04\x01\x02\x03' +
                        b'\x03\x04\x01\x02' +
                        b'\x02\x03\x04\x01',
        )

        block = ctypes.create_string_buffer(fixture.input, 16)

        # Act 
        aes.shift_rows(block, 3)
        actual = ctypes.string_at(block, 16)

        # Assert
        assert actual == fixture.expected

    # 
    # Test a real block
    # src: https://formaestudio.com/rijndaelinspector/archivos/Rijndael_Animation_v4_eng-html5.html
    def test_shiftrows_rijndael_block(self):
        fixture = UnitFixture(
                input = b'\xd4\xe0\xb8\x1e' +
                        b'\x27\xbf\xb4\x41' +
                        b'\x11\x98\x5d\x52' +
                        b'\xae\xf1\xe5\x30',

            expected = b'\xd4\xe0\xb8\x1e' +
                        b'\x41\x27\xbf\xb4' +
                        b'\x5d\x52\x11\x98' +
                        b'\xf1\xe5\x30\xae',
        )

        block = ctypes.create_string_buffer(fixture.input, 16)

        # Act 
        aes.shift_rows(block, 3)
        actual = ctypes.string_at(block, 16)

        # Assert
        assert actual == fixture.expected



class TestDecryptShiftRows:
    # 
    # DEFAULT SCENARIO: ROTATING A SINGLE WORD
    # 
    def test_rotword_left(self):
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
            aes._rot_word(word, 1)
            actual = ctypes.string_at(word, 4)

            # Assert
            assert actual == rot.expected

    def test_rotword_left_thrice(self):
        # Arrange
        fixture = UnitFixture(input=b"\x00\x01\x02\x03", expected=b"\x03\x00\x01\x02")
        word = ctypes.create_string_buffer(fixture.input, 4)

        # Act 
        aes._rot_word(word, 3)
        actual = ctypes.string_at(word, 4)

        # Assert
        assert actual == fixture.expected

    def test_shiftrows_rijndael_block_decrypt(self):
        fixture = UnitFixture(
                input = b'\xd4\xe0\xb8\x1e' +
                        b'\x41\x27\xbf\xb4' +
                        b'\x5d\x52\x11\x98' +
                        b'\xf1\xe5\x30\xae',
            expected = b'\xd4\xe0\xb8\x1e' +
                        b'\x27\xbf\xb4\x41' +
                        b'\x11\x98\x5d\x52' +
                        b'\xae\xf1\xe5\x30',


        )

        block = ctypes.create_string_buffer(fixture.input, 16)

        # Act 
        aes.invert_shift_rows(block, 3)
        actual = ctypes.string_at(block, 16)

        # Assert
        assert actual == fixture.expected