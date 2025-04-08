'''
    Check OS module
'''

import os
import platform

is_mac: bool = platform.system() == "Darwin"
is_sudo: bool = os.geteuid() == 0
