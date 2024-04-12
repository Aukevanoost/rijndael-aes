#
# UnitFixture: Helps with looping through multiple assertions
#
class UnitFixture: 
    def __init__(self, input, expected):
        self._input = input
        self._expected = expected

    @property
    def input(self): 
         return self._input 
    
    @property
    def expected(self): 
         return self._expected 
    

