# import ctypes
# from util.lib import aes, pretty_hex
# import aes_ref.aes as ref
# import copy
# from wrappers import UnitFixture

# class TestEncryptMixColumns: 
     
#     def test_column(self):
#         # Arrange
#         input = b'\x33\x55\x77\x99'
#         expected = bytearray(list(input))
#         word = copy.deepcopy(input)

#         # Act
#         ref.mix_single_column(expected)
#         aes._mix_column(word)
#         actual = ctypes.string_at(word, 4)

#         # Assert
#         assert expected.hex() == actual.hex()

#     def test_mixcolumns(self):
#         # The four numbers of one column are modulo multiplied in Rijndael's Galois Field by a given matrix.

#         input = b'\xd4\xe0\xb8\x1e'+\
#                 b'\xbf\xb4\x41\x27'+\
#                 b'\x5d\x52\x11\x98'+\
#                 b'\x30\xae\xf1\xe5' 
        
#         #print(pretty_hex(input))

#         expected = ref.bytes2matrix(input)
#         word = copy.deepcopy(input)
        
#         # Act
#         ref.mix_columns(expected)
#         aes.mix_columns(word)
#         actual = ctypes.string_at(word, 16)

#         # Assert
#         printable = ref.matrix2bytes(expected)
#         print(pretty_hex(printable))
#         print(pretty_hex(actual))

#         assert printable.hex() == actual.hex()

#     # def test_mixcolumns_rijndael_block(self):
#     #     # The four numbers of one column are modulo multiplied in Rijndael's Galois Field by a given matrix.

#     #     fixture = UnitFixture(
#     #             input = b'\xd4\xe0\xb8\x1e' +
#     #                     b'\xbf\xb4\x41\x27' +
#     #                     b'\x5d\x52\x11\x98' +
#     #                     b'\x30\xae\xf1\xe5',
                        
#     #          expected = b'\x04\xe0\x48\x28' +
#     #                     b'\x66\xcb\xf8\x06' +
#     #                     b'\x81\x19\xd3\x26' +
#     #                     b'\xe5\x9a\x7a\x4c',
#     #     )

#     #     block = ctypes.create_string_buffer(fixture.input, 16)

#     #     # Act 
#     #     aes.mix_columns(block)
#     #     actual = ctypes.string_at(block, 16)

#     #     # Assert
#     #     assert actual.hex() == fixture.expected.hex()
