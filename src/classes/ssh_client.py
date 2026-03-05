'''
    SSH client class
'''

from uuid import uuid4
from dataclasses import dataclass, field
from subprocess import run

DEFAULT_PORT: int = 22

class SshManException(Exception):
    '''
        SSH Manager Exception
    '''
    def __init__(self,
                 message: str) -> None:
        '''
            SSH Manager exception

            Args:
                message (str): Exception message
        '''
        super().__init__(message)


def get_uuid() -> str:
    '''
        Get a UUID

        Returns:
            str: UUID
    '''
    return str(uuid4())


@dataclass
class SshClient:
    '''
        SSH Client class
    '''
    host: str
    user: str
    password: str
    port: int = field(default = DEFAULT_PORT)
    favorite: bool = False
    client_id: str = field(default_factory = get_uuid)

    def connect(self) -> None:
        '''
            Connect to the SSH client
        '''
        try:
            print(f"Connecting to {self.user}@{self.host}:{self.port}")
            run(f"sshpass -p {self.password} ssh -p {self.port} {self.user}@{self.host}",
                shell = True, check = True) # pylint: pylint: disable=subprocess-run-check
        except Exception as e: # pylint: disable=broad-exception-caught
            print(f"Error: {e}")

    def ssh_format(self) -> str:
        '''
            Returns SSH format `<user>@<host>:<port>`
        '''
        return f"{self.user}@{self.host}:{self.port}"
