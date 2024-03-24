from ctypes import CDLL

rijndael = CDLL("./dist/rijndael.so")

def test_calculation():
    assert rijndael.sum(1,3) == 4