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
            sleep(2)
        except Exception as e: # pylint: disable=broad-exception-caught
            print(f"Error: {e}")
            sleep(2)


def clear_terminal() -> None:
    '''
        Clears terminal
    '''
    print("\033[H\033[J",
          end = "")


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

        Args:
            key: str
    '''
    try:
        data: dict = read_encrypted_json(file_path = data_path,
                                         password = key)
    except ValueError as ve:
        raise SshManException(message = "Maybe invalid decryption key.") from ve
    return sorted(clients_from_data(data["clients"]),
                  key = lambda client: f"{client.host}{client.user}{client.port}")


def print_clients(key: str | None,
                  clients: list[SSHClient] | None = None) -> None:
    '''
        Prints clients

        Args:
            key: str
            clients: list[SSHClient] | None
    '''
    clients: list[SSHClient] = get_clients(key = key)
    table_data: list[list[str]] = [[i + 1,
                                    client.host,
                                    client.user,
                                    client.port] for i, client in enumerate(clients)]
    clear_terminal()
    if clients:
        print("SSH MANAGER")
        print(tabulate(table_data,
                       headers = ["#",
                                  "Host",
                                  "User",
                                  "Port"],
                       tablefmt = "fancy_grid"))
    else:
        print("No clients found.")


def print_and_sleep(content: str = "",
                    sleep_timer: int = 2) -> None:
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
    print_and_sleep(content = "Client added successfully.")


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
        print_and_sleep(content = f"Error: {e}")


def command_remove(commands: str,
                   key: str) -> None:
    '''
        Removes client

        Args:
            commands: str
            key: str
    '''
    input_split: list[str] = commands.split(" ")
    client_id: str = input("Client ID: ") if len(input_split) == 1 else input_split[1]
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
                print_and_sleep(content = "Client removed successfully.")
        else:
            print_and_sleep(content = "Invalid client ID.")
    except ValueError:
        print_and_sleep(content = "Invalid client ID.")


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
        case _ if command.lower().startswith("password"):
            command_password(command = command,
                             key = key)
        case "exit":
            print("Bye!")
            sys_exit(0)
        case _:
            print_and_sleep(content = "Invalid command.")


def ssh_man() -> None:
    '''
        SSH Manager
    '''
    decrypt_key: str | None = getpass("Enter decryption key: ")
    create_env(decrypt_key)
    while True:
        try:
            print_clients(key = decrypt_key)
            print("Commands: connect, add, edit, remove, password, exit")
            user_input: str = input("> ")
            command_handle(command = user_input,
                           key = decrypt_key)
        except KeyboardInterrupt:
            print("\nBye!")
            sys_exit(0)


if __name__ == "__main__":
    ssh_man()
