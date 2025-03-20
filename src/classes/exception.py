'''
    Exception class
'''

class SshManException(Exception):
    '''
        SSH Manager exception class
    '''
    def __init__(self,
                 message: str | None = None):
        super().__init__(message or "An error occurred")
