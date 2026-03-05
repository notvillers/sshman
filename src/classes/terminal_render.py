'''
    Terminal render module
'''

import os
from dataclasses import dataclass, field
from tabulate import tabulate
from src.classes.ssh_client import SshClient
from src.classes.commands import Command

def clear_terminal() -> None:
    '''
        Clears the terminal
    '''
    print("\033[H\033[J",
          end = "")


def terminal_red(text: str) -> str:
    '''
        Returns red text

        Args:
            text (str): Text to colorize
    '''
    return f"\033[91m{text}\033[0m"


def terminal_yellow(text: str) -> str:
    '''
        Returns yellow text

        Args:
            text (str): Text to colorize
    '''
    return f"\033[93m{text}\033[0m"


def terminal_purple(text: str) -> str:
    '''
        Returns purple text

        :param text: :class:`str`
    '''
    return f"\033[95m{text}\033[0m"


def get_terminal_width() -> int:
    '''
        Get the terminal width
    '''
    return os.get_terminal_size().columns or None


class ClientRender:
    '''
        Client render class
    '''
    def __init__(self,
                 c: SshClient,
                 enum: int | None = None) -> None:
        '''
            Client render class

            Args:
                client (SshClient): SSH client
                enum (int): Enumerated value
        '''
        self.row_num: str = str(enum) if enum else ""
        self.host: str = f"{c.host}{terminal_yellow(" *") if c.favorite else ""}"
        self.user: str = c.user
        self.port: int = c.port


def sort_clients(clients: list[SshClient]) -> list[SshClient]:
    '''
        Sort the clients

        Args:
            c (list[SshClient]): List of SSH clients
    '''
    return sorted(clients,
                  key = lambda c: f"{0 if c.favorite else 1 }{c.host}{c.user}{c.port}")


def client_id_from_enum(clients: list[SshClient],
                        enum: int,
                        start_num: int = 1) -> str:
    '''
        Get the client ID from the enumerated value

        Args:
            clients (list[SshClient]): List of SSH clients
            enum (int): Enumerated value
            start_num (int): Starting number
    '''
    clients = sort_clients(clients)
    i: int = enum - start_num
    if i < 0 or i >= len(clients):
        return None
    return clients[i].client_id


def client_from_client_id(clients: list[SshClient],
                          client_id: str) -> SshClient:
    '''
        Get the client from the client ID

        Args:
            clients (list[SshClient]): List of SSH clients
            client_id (str): Client ID
    '''
    for client in clients:
        if client.client_id == client_id:
            return client
    return None


def client_from_enum(clients: list[SshClient],
                     enum: int,
                     start_num: int = 1) -> SshClient:
    '''
        Get the client from the enumerated value

        Args:
            clients (list[SshClient]): List of SSH clients
            enum (int): Enumerated value
            start_num (int): Starting number
    '''
    client_id: str = client_id_from_enum(clients,
                                         enum,
                                         start_num)
    if client_id:
        return client_from_client_id(clients,
                                     client_id)
    return None


@dataclass
class TerminalRender:
    '''
        Terminal render class
    '''
    width: int = field(default_factory = get_terminal_width)
    title: str = "SSH Client Manager"
    clients: list[SshClient] = field(default_factory = [])
    commands: list[Command] = field(default_factory = [])

    def __init__(self) -> None:
        self.clients = sort_clients(self.clients)

    def get_client(self) -> str:
        '''
            Render the title
        '''
        return self.title.center(self.width)


    def get_clients(self) -> str:
        '''
            Render the clients
        '''
        table = []
        for i, client in enumerate(self.clients):
            cr: ClientRender = ClientRender(client,
                                            i + 1)
            row: list = [cr.row_num,
                         cr.host,
                         cr.user,
                         cr.port]
            table.append(row)
        return tabulate(table,
                        headers = ["", "Host", "User", "Port"],
                        tablefmt = "simple_grid")

    def get_commands(self) -> str:
        '''
            Render the commands
        '''
        table = []
        for c in self.commands:
            command_str: str = f"{c.long} {(" (" + c.short + ")") if c.short else ""}"
            row: list = [command_str,
                         c.description or ""]
            table.append(row)
        return tabulate(table,
                        headers = ["Command", "Description"])
