'''
    Commands class
'''

from dataclasses import dataclass

@dataclass
class Command:
    '''
        Command class
    '''
    long: str
    short: str
    description: str
    function: callable
    args: list
