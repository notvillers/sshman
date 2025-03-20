'''
    SSH Client class
'''

from dataclasses import dataclass, field
from uuid import uuid4

def gen_uuid() -> str:
    '''
        Generate a UUID
    '''
    return str(uuid4())


@dataclass
class SSHClient:
    '''
        SSH Client class
    '''
    host: str
    user: str
    password: str
    port: int = 22