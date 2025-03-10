'''
    SSH Manager
'''
import os
from sys import exit as sys_exit
import base64
import json
from typing import Tuple
from dataclasses import dataclass
from subprocess import run
from time import sleep
from getpass import getpass
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import scrypt
from tabulate import tabulate

path: str = os.path.abspath(os.path.dirname(__file__))
data_path: str = os.path.join(path,
                              "data.json.enc")
DEFAULT_DATA_DICT: dict = {"clients": []}
DEFAULT_PORT: int = 22

@dataclass
class TerminalCode:
    '''
        Terminal codes dataclass
    '''
    clear: str = "\033[H\033[J"


term_code: TerminalCode = TerminalCode()


def clear_terminal() -> None:
    '''
        Clears terminal
    '''
    print(term_code.clear)


@dataclass
class SSHClient:
    '''
        SSH Client dataclass
    '''
    host: str
    user: str
    password: str
    port: int = DEFAULT_PORT

    def connect(self) -> None:
        '''
            Connect to SSH client
        '''
        try:
            print(f"Connecting to {self.user}@{self.host}...")
            run(f"sshpass -p {self.password} ssh -p {self.port} {self.user}@{self.host}", # pylint: disable=subprocess-run-check
                shell = True)
            print(f"Connection to {self.user}@{self.host} closed.")
            sleep(2)
        except Exception as e: # pylint: disable=broad-exception-caught
            print(f"Error: {e}")
            sleep(2)


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
    return SSHClient(host = client_data["host"],
                     user = client_data["user"],
                     password = client_data["password"],
                     port = client_data["port"])


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
    '''
    data: dict = read_encrypted_json(file_path = data_path,
                                     password = key)
    return clients_from_data(data["clients"])


def print_clients(key: str) -> None:
    '''
        Prints clients
    '''
    clients: list[SSHClient] = get_clients(key = key)
    table_data: list[list[str]] = [[i + 1,
                                    client.host,
                                    client.user,
                                    client.port] for i, client in enumerate(clients)]
    clear_terminal()
    if clients:
        print(tabulate(table_data,
                       headers = ["#",
                                  "Host",
                                  "User",
                                  "Port"],
                       tablefmt = "fancy_grid"))
    else:
        print("No clients found.")


def command_connect(command: str,
                    key: str) -> None:
    '''
        Connects to client

        Args:
            command: str
            key: str
    '''
    user_input_split: list[str] = command.split(" ")
    client_id: str = input("Client ID: ") if len(user_input_split) == 1 else user_input_split[1]
    try:
        client_id_int: int = int(client_id)
        clients: list[SSHClient] = get_clients(key = key)
        if 0 < client_id_int <= len(clients):
            clients[client_id_int - 1].connect()
        else:
            print("Invalid client ID.")
            sleep(2)
    except ValueError:
        print("Invalid client ID.")
        sleep(2)


def command_add(key = str) -> None:
    '''
        Adds client

        Args:
            key: str
    '''
    host: str = input("Enter host: ")
    user: str = input("Enter user: ")
    password: str = getpass("Enter password: ")
    port: int = input("Enter port: (default 22)")
    data: dict = read_encrypted_json(file_path = data_path,
                                    password = key)
    data["clients"].append({"host": host,
                            "user": user,
                            "password": password,
                            "port": int(port) if port and isinstance(port, int) else 22})
    save_and_encrypt_data(data = data,
                          file_path = data_path,
                          password = key)
    print("Client added successfully.")
    sleep(2)


def command_edit(commands: str,
                 key: str) -> None:
    '''
        Edits client

        Args:
            commands: str
            key: str
    '''
    user_input_split: list[str] = commands.split(" ")
    client_id: str = input("Client ID: ") if len(user_input_split) == 1 else user_input_split[1]
    try:
        client_id_int: int = int(client_id)
        clients: list[SSHClient] = get_clients(key = key)
        if 0 < client_id_int <= len(clients):
            client: SSHClient = clients[client_id_int - 1]
            print("Edit client:")
            host: str = input(f"Enter host ({client.host}): ") or client.host
            user: str = input(f"Enter user ({client.user}): ") or client.user
            password: str = getpass("Enter password: ") or client.password
            port: str = input(f"Enter port ({client.port}): ") or client.port
            port_int: int = DEFAULT_PORT
            try:
                port_int = int(port)
            except ValueError:
                pass
            data: dict = read_encrypted_json(file_path = data_path,
                                            password = key)
            data["clients"][client_id_int - 1] = {"host": host,
                                                  "user": user,
                                                  "password": password,
                                                  "port": port_int} # pylint: disable=line-too-long
            save_and_encrypt_data(data = data,
                                  file_path = data_path,
                                  password = key)
            print("Client updated successfully.")
            sleep(2)
    except Exception as e: # pylint: disable=broad-exception-caught
        print(f"Error: {e}")
        sleep(2)


def command_remove(commands: str,
                   key: str) -> None:
    '''
        Removes client

        Args:
            commands: str
            key: str
    '''
    user_input_split: list[str] = commands.split(" ")
    client_id: str = input("Client ID: ") if len(user_input_split) == 1 else user_input_split[1]
    try:
        client_id_int: int = int(client_id)
        data: dict = read_encrypted_json(file_path = data_path,
                                        password = key)
        clients: list[dict] = data["clients"]
        if 0 < client_id_int <= len(clients):
            confirm: str = input("Are you sure you want to remove this client? (y/N): ")
            if confirm.lower() == "y":
                clients.pop(client_id_int - 1)
                save_and_encrypt_data(data = data,
                                      file_path = data_path,
                                      password = key)
                print("Client removed successfully.")
                sleep(2)
        else:
            print("Invalid client ID.")
            sleep(2)
    except ValueError:
        print("Invalid client ID.")
        sleep(2)


def command_handle(command: str,
                   key: str) -> None:
    '''
        Handles commands
    '''
    match command.lower():
        case _ if command.lower().startswith("connect"):
            command_connect(command = command,
                            key = key)
        case "add":
            command_add(key = key)
        case _ if command.lower().startswith("edit"):
            command_edit(commands = command,
                         key = key)
        case _ if command.lower().startswith("remove"):
            command_remove(commands = command,
                           key = key)
        case "exit":
            print("Bye!")
            sys_exit(0)
        case _:
            print("Invalid command.")
            sleep(2)


def ssh_man() -> None:
    '''
        SSH Manager
    '''
    decrypt_key: str | None = getpass("Enter decryption key: ")
    create_env(decrypt_key)
    while True:
        try:
            print_clients(key = decrypt_key)
            print("Commands: connect, add, edit, remove, exit")
            user_input: str = input("> ")
            command_handle(command = user_input,
                           key = decrypt_key)
        except KeyboardInterrupt:
            print("\nBye!")
            sys_exit(0)


if __name__ == "__main__":
    ssh_man()
