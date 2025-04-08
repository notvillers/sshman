'''
    Keyboard input module
'''
from getkey import getkey, keys
import src.check_os as c_os

ESCAPE_EVENT: str = "esc"
ENTER_EVENT: str = "enter"
BACKSPACE_EVENT: str = "backspace"

def get_input(placeholder: str = ">") -> str | None:
    '''
        Gets input from the user.

        Args:
            placeholder (str): The placeholder to display.
    '''
    if c_os.is_mac and not c_os.is_sudo:
        return input(f"{placeholder} ")
    return keyboard_event_input(placeholder)


def keyboard_event_input(placeholder: str = ">") -> str | None:
    '''
        Gets input from the user.

        Args:
            placeholder (str): The placeholder to display.
    '''
    print(f"{placeholder} ",
          end = '',
          flush = True)
    chars: list[str] = []
    while True:
        var: str = getkey()
        match var:
            case keys.ESC:
                return None
            case keys.ENTER:
                print()
                return ''.join(chars)
            case keys.BACKSPACE:
                if chars:
                    chars.pop()
                    print('\b \b',
                          end = '',
                          flush = True)
                    continue
            case _:
                chars.append(var)
                print(var,
                      end = '',
                      flush = True)
                continue
