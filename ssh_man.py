'''
    SSH Manager
'''
import os
from sys import exit as sys_exit
import base64
import json
from typing import Tuple
from dataclasses import dataclass, field
from subprocess import run
from time import sleep
from uuid import uuid4
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import scrypt
from tabulate import tabulate

first_run: bool = True
path: str = os.path.abspath(os.path.dirname(__file__))
data_path: str = os.path.join(path,
                              "data.aes")
DEFAULT_DATA_DICT: dict = {"clients": []}
DEFAULT_PORT: int = 22
SLEEP_TIMER: float = 1.5

class SshManException(Exception):
    '''
        SSH Manager Exception
    '''
    def __init__(self,
                 message: str) -> None:
        '''
            SSH Manager Exception

            Args:
                message: str
        '''
        super().__init__(message)


def get_uuid() -> str:
    '''
        Gets UUID
    '''
    return str(uuid4())

#TODO: keygen remove
#TODO: enable fingerprint
#TODO: handling too small terminal size (min. width: 96)
@dataclass()
class SSHClient:
    '''
        SSH Client dataclass
    '''
    host: str
    user: str
    password: str
    port: int = field(default = DEFAULT_PORT)
    favorite: bool = False
    client_id: str = field(default_factory = get_uuid)

    def connect(self) -> None:
        '''
            Connect to SSH client
        '''
        try:
            print(f"Connecting to {self.user}@{self.host}...")
            run(f"sshpass -p {self.password} ssh -p {self.port} {self.user}@{self.host}", # pylint: disable=subprocess-run-check
                shell = True)
            sleep(SLEEP_TIMER)
        except Exception as e: # pylint: disable=broad-exception-caught
            print(f"Error: {e}")
            sleep(SLEEP_TIMER)


filtered_clients: list[SSHClient] = []
filter_key: str | None = None
filtered: bool = False
filter_info: str | None = None

def clear_terminal() -> None:
    '''
        Clears terminal
    '''
    print("\033[H\033[J",
          end = "")


def terminal_red(text: str) -> str:
    '''
        Terminal red text

        Args:
            text: str
    '''
    return f"\033[91m{text}\033[0m"


def terminal_yellow(text: str) -> str:
    '''
        Terminal yellow text

        Args:
            text: str
    '''
    return f"\033[93m{text}\033[0m"


def dict_to_json(data: dict,
                 file_path: str,
                 encoding: str = "utf-8-sig") -> None:
    '''
        Converts dictionary to JSON

        Args:
            data: dict
            data_path: str
    '''
    with open(file_path,
              "w",
              encoding = encoding) as file:
        json.dump(data,
                  file,
                  indent = 4)


def encrypt_data(file_path: str,
                 password: str,
                 encoding: str = "utf-8-sig") -> None:
    '''
        Encrypts file data

        Args:
            file_path: str
            password: str
            encoding: str
    '''
    salt: bytes = os.urandom(16)
    key: bytes | Tuple[bytes] = scrypt(password = password.encode(),
                                       salt = salt,
                                       key_len = 32,
                                       N = 2**14,
                                       r = 8,
                                       p = 1)
    cipher: AES = AES.new(key,
                          AES.MODE_CBC)
    with open(file_path,
              "r",
              encoding = encoding) as file:
        data: str = file.read()
    padded_data: bytes = pad(data.encode(),
                             AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    encrypted_content = salt + cipher.iv + encrypted_data
    encrypted_string = base64.b64encode(encrypted_content).decode(encoding)
    with open(file_path,
              "w",
              encoding = encoding) as file:
        file.write(encrypted_string)


def decrypt_data(file_path: str,
                 password: str,
                 encoding: str = "utf-8-sig") -> str:
    '''
        Decrypts file data

        Args:
            data_path: str
            password: str
            encoding: str
    '''
    with open(file_path,
              "rb") as file:
        encrypted_string: str = file.read()
    encrypted_content: bytes = base64.b64decode(encrypted_string)
    salt: bytes = encrypted_content[:16]
    iv: bytes = encrypted_content[16:32]
    encrypted_data: bytes = encrypted_content[32:]
    key: bytes | Tuple[bytes] = scrypt(password = password.encode(),
                                       salt = salt,
                                       key_len = 32,
                                       N = 2**14,
                                       r = 8,
                                       p = 1)
    cipher = AES.new(key,
                     AES.MODE_CBC,
                     iv = iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data),
                           AES.block_size)
    return decrypted_data.decode(encoding)


def json_str_to_dict(data: str) -> dict:
    '''
        Converts JSON string to dictionary

        Args:
            data: str
    '''
    return json.loads(data)


def save_and_encrypt_data(data: dict,
                          file_path: str,
                          password: str) -> None:
    '''
        Saves and encrypts data

        Args:
            data: dict
            file_path: str
            password: str
    '''
    dict_to_json(data = data,
                 file_path = file_path)
    encrypt_data(file_path = file_path,
                 password = password)


def create_env(key) -> None:
    '''
        Creates environment
    '''
    if key:
        if not os.path.exists(data_path):
            save_and_encrypt_data(data = DEFAULT_DATA_DICT,
                                  file_path = data_path,
                                  password = key)
    else:
        print("Decryption key is required.")
        sys_exit(1)


def read_encrypted_json(file_path: str,
                        password: str) -> dict:
    '''
        Reads encrypted JSON file

        Args:
            file_path: str
            password: str
    '''
    return json_str_to_dict(decrypt_data(file_path,
                                         password))


def client_from_data(client_data: dict) -> SSHClient:
    '''
        Creates SSHClient object from data

        Args:
            client_data: dict
    '''
    return SSHClient(client_id = client_data["client_id"],
                     host = client_data["host"],
                     user = client_data["user"],
                     password = client_data["password"],
                     port = client_data["port"],
                     favorite = client_data["favorite"] if "favorite" in client_data else False)


def clients_from_data(client_datas: list[dict]) -> list[SSHClient]:
    '''
        Creates SSHClient objects from data

        Args:
            client_datas: list[dict]
    '''
    return [client_from_data(client_data) for client_data in client_datas]


def get_clients(key: str) -> list[SSHClient]:
    '''
        Gets clients

        Args:
            key: str
    '''
    try:
        data: dict = read_encrypted_json(file_path = data_path,
                                         password = key)
    except ValueError as ve:
        raise SshManException(message = "Maybe invalid decryption key.") from ve
    return sorted(clients_from_data(data["clients"]),
                  key = lambda c: f"{0 if c.favorite else 1}{c.host}{c.user}{c.port}")


def current_clients(key: str) -> list[SSHClient]:
    '''
        Current clients

        Args:
            key: str
    '''
    if filtered:
        return filtered_clients
    return get_clients(key = key)


def get_client_id(clients: list[SSHClient],
                  input_id: str) -> int:
    '''
        Gets client ID

        Args:
            clients: list[SSHClient]
            filter: str | int
    '''
    if input_id.isdigit():
        input_id_int: int = int(input_id)
        if 0 < input_id_int <= len(clients):
            return clients[input_id_int - 1].client_id
        print_and_sleep(content = "Invalid client ID.")
        return None
    for client in clients:
        client_ids: list[int] = []
        for client in clients:
            if input_id in f"{client.host}{client.user}{client.port}":
                client_ids.append(client.client_id)
        if len(client_ids) == 1:
            return client_ids[0]
        print_and_sleep(content = "Multiple clients found, be more specific.")
        return None


def get_client_by_client_id(clients: list[SSHClient],
                            client_id: int) -> SSHClient | None:
    '''
        Gets client by client ID

        Args:
            clients: list[SSHClient]
            client_id: int
    '''
    for client in clients:
        if client.client_id == client_id:
            return client
    return None


def get_filter() -> str:
    '''
        Prints filter info
    '''
    if filtered and filter_info:
        text: str = "FILTERED"
        if filter_info:
            text += f" - {filter_info}"
        return terminal_red(text if text else "")
    return ""


def print_and_sleep(content: str = "",
                    sleep_timer: int = SLEEP_TIMER) -> None:
    '''
        Prints content and sleeps

        Args:
            content: str
            sleep_timer: int
    '''
    print(content)
    sleep(sleep_timer)


def find_client(search: str,
                key: str) -> SSHClient | None:
    '''
        Finds clients

        Args:
            search: str
            key: str
    '''
    clients: list[SSHClient] = get_clients(key = key)
    if search.isdigit():
        try:
            index: int = int(search) - 1
            if 0 <= index < len(clients):
                return clients[index]
        except ValueError:
            print_and_sleep(content = "Invalid client ID.")
    else:
        found_clients: list[SSHClient] | None = []
        for client in clients:
            if search in f"{client.user}@{client.host}:{client.port}":
                found_clients.append(client)
        if len(found_clients) == 1:
            return found_clients[0]
        elif len(found_clients) > 1:
            print("Multiple clients found:")
            for i, client in enumerate(found_clients):
                print(f"{i + 1}. {client.user}@{client.host}:{client.port}")
            print("Please use client ID or be more specific.")
            sleep(2)
            return None
    return None


def get_clients_dict(key: str) -> list[dict]:
    '''
        Gets clients dictionary

        Args:
            key: str
    '''
    clients_dict: dict = [client.__dict__ for client in get_clients(key = key)]
    return sorted(clients_dict,
                  key = lambda c: f"{0 if c['favorite'] else 1}{c['host']}{c['user']}{c['port']}")


def save_clients_dict(clients_dict: list[dict],
                      key: str) -> None:
    '''
        Saves clients dictionary

        Args:
            clients_dict: list[dict]
            key: str
    '''
    data: dict = read_encrypted_json(file_path = data_path,
                                     password = key)
    data["clients"] = clients_dict
    save_and_encrypt_data(data = data,
                          file_path = data_path,
                          password = key)


def command_connect(command: str,
                    key: str) -> None:
    '''
        Connects to client

        Args:
            command: str
            key: str
    '''
    input_split: list[str] = command.split(" ")
    search: str = input("Client ID: ") if len(input_split) == 1 else input_split[1]
    client: SSHClient | None = find_client(search = search,
                                           key = key)
    if client:
        client.connect()


def filter_clients(clients: list[SSHClient],
                   filter_text: str) -> list[SSHClient]:
    '''
        Filters clients

        Args:
            clients: list[SSHClient]
            filter: str
    '''
    filtereds: list[SSHClient] = []
    for client in clients:
        if filter_text in f"{client.host}{client.user}{client.port}".lower():
            filtereds.append(client)
    return filtereds


def global_filter(clients: list[SSHClient] | None = None,
                  filter_str: str | None = None) -> None:
    '''
        Global filter

        Args:
            client: list[SSHClient] | None (default None)
    '''
    global filtered_clients # pylint: disable=global-statement
    global filtered # pylint: disable=global-statement
    global filter_key # pylint: disable=global-statement
    if clients:
        filtered_clients = filter_clients(clients = clients,
                                          filter_text = filter_str)
        filtered = True
    else:
        filtered_clients = []
        filtered = False
    filter_key = filter_str or None


def global_filter_info(text: str | None = None) -> None:
    '''
        Global filter info

        Args:
            text: str | None
    '''
    global filter_info # pylint: disable=global-statement
    filter_info = text


def command_filter(commands: str,
                   key: str) -> None:
    '''
        Filters clients

        Args:
            commands: str
            key: str
    '''
    input_split: list[str] = commands.split(" ")
    filter_text: str = input("Filter: ") if len(input_split) == 1 else input_split[1]
    if filtered_clients and not filter_text:
        global_filter()
        global_filter_info()
        return
    global_filter(clients = get_clients(key = key),
                  filter_str = filter_text)
    if filter_text and filtered and not filtered_clients:
        global_filter_info(text = f"No clients found for '{filter_text}'.")
    if filter_text and filtered and filtered_clients:
        global_filter_info(text = f"Clients for '{filter_text}'.")
    if not filter_text:
        global_filter()
        global_filter_info()


def command_unfilter() -> None:
    '''
        Unfilters clients
    '''
    global_filter()
    global_filter_info()


def command_add(key = str) -> None:
    '''
        Adds client

        Args:
            key: str
    '''
    host: str = input("Enter host: ")
    user: str = input("Enter user: ")
    password: str = getpass("Enter password: ")
    port: int = input(f"Enter port (default {DEFAULT_PORT}): ")
    if not host or not user or not password:
        print_and_sleep(content = "Host, user and password are required.")
        return
    new_client: SSHClient = SSHClient(host = host,
                                      user = user,
                                      password = password,
                                      port = port or DEFAULT_PORT)
    clients_dict: list[dict] = get_clients_dict(key = key)
    clients_dict.append(new_client.__dict__)
    save_clients_dict(clients_dict = clients_dict,
                      key = key)
    print_and_sleep(f"Client added under '{new_client.client_id}' ID")
    if filtered:
        global_filter(clients = get_clients(key = key),
                      filter_str = filter_key)


def update_client(client: SSHClient) -> SSHClient:
    '''
        Updates client

        Args:
            client: SSHClient
    '''
    client.host = input(f"Enter host ({client.host}): ") or client.host
    client.user = input(f"Enter user ({client.user}): ") or client.user
    client.password = getpass("Enter password: ") or client.password
    client.port = input(f"Enter port ({client.port}): ") or client.port
    return client


def update_clients(clients: list[SSHClient],
                   client_id: str) -> list[SSHClient]:
    '''
        Updates client

        Args:
            clients: list[SSHClient]
            client_id: str
    '''
    for client in clients:
        if client.client_id == client_id:
            client = update_client(client = client)
            break
    return clients


def command_edit(commands: str,
                 key: str) -> None:
    '''
        Edits client

        Args:
            commands: str
            key: str
    '''
    input_split: list[str] = commands.split(" ")
    client_id: str = input("Client ID: ") if len(input_split) == 1 else input_split[1]
    clients: list[SSHClient] = get_clients(key = key)
    client_id_int: int | None = get_client_id(clients = clients,
                                                  input_id = client_id)
    if client_id_int is not None:
        clients = update_clients(clients = clients,
                                 client_id = client_id_int)
        save_clients_dict(clients_dict = [client.__dict__ for client in clients],
                          key = key)
    if filtered:
        global_filter(clients = clients,
                      filter_str = filter_key)


def client_remove(clients: list[SSHClient],
                  client_id: str) -> list[SSHClient]:
    '''
        Removes client

        Args:
            clients: list[SSHClient]
            client_id: str
    '''
    for i, client in enumerate(clients):
        if client.client_id == client_id:
            client_rm: SSHClient = client
            clients.pop(i)
            print_and_sleep(content = f"Client {client_rm.user}@{client_rm.host} removed.")
            break
    return clients


def command_remove(commands: str,
                   key: str) -> None:
    '''
        Removes client

        Args:
            commands: str
            key: str
    '''
    input_split: list[str] = commands.split(" ")
    shown_clients: list[SSHClient] = filtered_clients or get_clients(key = key)
    clients: list[SSHClient] = get_clients(key = key)
    client_id: str = input("Client ID: ") if len(input_split) == 1 else input_split[1]
    client_id_int: int | None = get_client_id(clients = shown_clients,
                                              input_id = client_id)
    if client_id_int is not None:
        confirm: str = input("Are you sure you want to remove the client? (y/N): ")
        if confirm.lower() == "y":
            clients = client_remove(clients = clients,
                                    client_id = client_id_int)
            save_clients_dict(clients_dict = [client.__dict__ for client in clients],
                              key = key)
        else:
            print_and_sleep(content = "Client removal cancelled.")
        if filtered_clients:
            filter_clients(clients = clients,
                           filter_text = filter_key)


def favoutite_client(clients: list[SSHClient],
                     client_id: str) -> list[SSHClient]:
    '''
        Favorites client

        Args:
            clients: list[SSHClient]
            client_id: str
    '''
    for client in clients:
        if client.client_id == client_id:
            client.favorite = not client.favorite
            print_and_sleep(f"Client {client.user}@{client.host} {'favorited' if client.favorite else 'unfavorited'}.") # pylint: disable=line-too-long
            break
    return clients


def command_favorite(commands: str,
                     key: str) -> None:
    '''
        Favorites client

        Args:
            commands: str
            key: str
    '''
    input_split: list[str] = commands.split(" ")
    shown_clients: list[SSHClient] = filtered_clients or get_clients(key = key)
    clients: list[SSHClient] = get_clients(key = key)
    client_id: str = input("Client ID: ") if len(input_split) == 1 else input_split[1]
    client_id_int: int | None = get_client_id(clients = shown_clients,
                                              input_id = client_id)
    if client_id_int is not None:
        clients = favoutite_client(clients = clients,
                                   client_id = client_id_int)
        save_clients_dict(clients_dict = [client.__dict__ for client in clients],
                          key = key)
        if filtered_clients:
            global_filter(clients = clients,
                          filter_str = filter_key)


def command_password(command: str,
                     key: str) -> None:
    '''
        Change password on encrypted file

        Args:
            command: str
            key: str
    '''
    input_split: list[str] = command.split(" ")
    old_pw: str = getpass("Enter old password: ") if len(input_split) < 3 else input_split[1]
    new_pw: str = getpass("Enter new password: ") if len(input_split) < 3 else input_split[2]
    conf_new_pw: str = getpass("Confirm new password: ") if len(input_split) < 3 else input_split[2]
    if old_pw and new_pw and conf_new_pw:
        if key == old_pw:
            if new_pw == conf_new_pw:
                confirm: str = input("Are you sure you want to change the password? (y/N): ")
                if confirm.lower() == "y":
                    data: dict = read_encrypted_json(file_path = data_path,
                                                     password = key)
                    save_and_encrypt_data(data = data,
                                          file_path = data_path,
                                          password = new_pw)
                    clear_terminal()
                    print("Password changed successfully, please restart.")
                    sys_exit(0)
                else:
                    print_and_sleep(content = "Password change cancelled.")
            else:
                print_and_sleep(content = "New passwords do not match.")
        else:
            print_and_sleep(content = "Invalid old password.")


def command_export(command: str,
                   key: str) -> None:
    '''
        Exports clients

        Args:
            command: str
            key: str
    '''
    input_split: list[str] = command.split(" ")
    password: str = getpass("Enter password: ") if len(input_split) == 1 else input_split[1]
    file_path: str = input("Enter file path: ") if len(input_split) < 3 else input_split[2]
    confirm: str = input("Are you sure you want to export clients? (y/N): ")
    if not password or not file_path:
        print_and_sleep(content = "Password and file path are required.")
    elif confirm.lower() != "y":
        print_and_sleep(content = "Export cancelled.")
    elif password and file_path and password == key:
        data: dict = read_encrypted_json(file_path = data_path,
                                         password = key)
        dict_to_json(data = data,
                     file_path = file_path)
        print_and_sleep(content = f"Clients exported successfully to '{file_path}'.")
    elif password != key:
        print_and_sleep(content = "Invalid password.")
    else:
        if not password or not file_path:
            errors: list[str] = []
            if not password:
                errors.append("Password is required.")
            if not file_path:
                errors.append("File path is required.")
            print_and_sleep(content = "\n".join(errors))


def command_handle(command: str,
                   key: str) -> None:
    '''
        Handles commands
    '''
    match command.lower():
        # connect
        case _ if command.lower().startswith("connect") or command.lower().split(" ")[0] == "c":
            command_connect(command = command,
                            key = key)
        # filter
        case _ if command.lower().startswith("filter") or command.lower().split(" ")[0] == "f":
            command_filter(commands = command,
                           key = key)
        # unfilter
        case _ if command in ["unfilter", "u"]:
            command_unfilter()
        # add
        case _ if command in ["add", "a"]:
            command_add(key = key)
        # edit
        case _ if command.lower().startswith("edit") or command.lower().split(" ")[0] == "e":
            command_edit(commands = command,
                         key = key)
        # remove
        case _ if command.lower().startswith("remove") or command.lower().split(" ")[0] == "r":
            command_remove(commands = command,
                           key = key)
        # favorite
        case _ if command.lower().startswith("favorite") or command.lower().split(" ")[0] == "fav":
            command_favorite(commands = command,
                             key = key)
        # password
        case _ if command.lower().startswith("password") or command.lower().split(" ")[0] == "p":
            command_password(command = command,
                             key = key)
        # export
        case _ if command.lower().startswith("export") or command.lower().split(" ")[0] == "exp":
            command_export(command = command,
                           key = key)
        # exit
        case "exit":
            print("Bye!")
            sys_exit(0)
        # default
        case _:
            print_and_sleep(content = "Invalid command.")


def print_first_run() -> None:
    '''
        Prints first run text
    '''
    if not os.path.exists(data_path):
        text: str = "Welcome to SSH Manager!"
        text += "\nPlase provide a decryption key (password)."
        text += "\nYou can change the password later!"
        print(text)
        global first_run # pylint: disable=global-statement
        first_run = False


def terminal_width() -> int:
    '''
        Terminal width
    '''
    return os.get_terminal_size().columns


def small_render() -> bool:
    '''
        Small render
    '''
    return terminal_width() < 96


def print_clients(key: str | None) -> None:
    '''
        Prints clients

        Args:
            key: str
            clients: list[SSHClient] | None
    '''
    clients: list[SSHClient] = []
    if filtered:
        clients = filtered_clients
    else:
        clients: list[SSHClient] = clients or get_clients(key = key)
    table_data: list[list[str]] = [[i + 1,
                                    c.host + (f" {terminal_yellow("*")}" if c.favorite else ""),
                                    c.user,
                                    c.port] for i, c in enumerate(clients)]
    clear_terminal()
    print("SSH Manager")
    ssh_table: str = tabulate(table_data,
                                headers = ["#",
                                            "Host",
                                            "User",
                                            "Port"],
                                tablefmt = "simple_grid")
    ssh_table += f"\n{get_filter()}"
    command_data: list[list[str]] = [["Connect (c)", "Connects to client"],
                                     ["Add (a)", "Adds new client"],
                                     ["Edit (e)", "Edits client"],
                                     ["Remove (r)", "Removes client"],
                                     ["Filter (f)", "Filters clients"],
                                     ["Favorite (fav)", f"Favorites client {terminal_yellow('*')}"],
                                     ["Password (p)", "Changes password"],
                                     ["Export (exp)", "Exports to decrypted .json"],
                                     ["Exit (CTRL+C)", "Exits SSH Manager"]]
    commands_table: str = tabulate(command_data,
                                    headers = ["Command",
                                                "Description"])
    grid: list[list[str]] = [[ssh_table,
                                commands_table]]
    print(tabulate(grid,
                    headers = ["SSH Clients",
                                "Commands"],
                    tablefmt = "simple_grid"))


def print_home(key: str) -> None:
    '''
        Prints home
    '''
    print_clients(key = key)


def ssh_man() -> None:
    '''
        SSH Manager
    '''
    if first_run:
        print_first_run()
    decrypt_key: str | None = getpass("Enter decryption key: ")
    create_env(decrypt_key)
    while True:
        try:
            print_home(key = decrypt_key)
            command_handle(command = input("> "),
                           key = decrypt_key)
        except KeyboardInterrupt:
            print("\nBye!")
            sys_exit(0)


if __name__ == "__main__":
    ssh_man()
