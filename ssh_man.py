'''
    SSH Manager
'''
import os
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
decrypt_key: str | None = None

@dataclass
class TerminalCode:
    '''
        Terminal codes dataclass
    '''
    clear: str = "\033[H\033[J"

term_code: TerminalCode = TerminalCode()

@dataclass
class Client:
    '''
        SSH Client dataclass
    '''
    host: str
    user: str
    password: str
    port: int = 22


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

decrypt_key = getpass("Enter decryption key: ")

if not os.path.exists(data_path):
    dict_to_json(DEFAULT_DATA_DICT,
                 data_path)
    encrypt_data(data_path,
                 decrypt_key)

ssh_data: dict = json_str_to_dict(decrypt_data(data_path,
                                            decrypt_key))

def client_data_to_client(client_data: dict) -> Client:
    '''
        Converts client data to client

        Args:
            client_data: dict
    '''
    return Client(host = client_data["host"],
                  user = client_data["user"],
                  password = client_data["password"],
                  port = client_data["port"])

def clients_data_to_client(clients_data: list[dict]) -> list[Client]:
    '''
        Converts clients data to clients

        Args:
            clients_data: list[dict]
    '''
    return [client_data_to_client(client_data) for client_data in clients_data]

def create_client_cli() -> Client:
    '''
        Creates client from CLI
    '''
    hostname: str = input("Enter hostname: ")
    username: str = input("Enter username: ")
    password: str = getpass("Enter password: ")
    port: int = input("Enter port: (default 22) ")
    return Client(host = hostname,
                  user = username,
                  password = password,
                  port = 22 if not port else int(port))

def print_clients(client_list: list[Client]) -> None:
    '''
        Prints clients

        Args:
            clients: list[Client]
    '''
    header: list[str] = ["#", "Host", "User", "Port"]
    data: list = [[i+1, c.host, c.user, c.port] for i, c in enumerate(client_list)]
    print(term_code.clear)
    print(tabulate(data,
                   headers = header,
                   tablefmt = "fancy_grid"))


def ssh_connect(c: Client) -> None:
    '''
        Connects to SSH client

        Args:
            c: Client
    '''
    ssh_command: str = f"sshpass -p {c.password} ssh -p {c.port} {c.user}@{c.host}"
    run(ssh_command, # pylint: disable=subprocess-run-check
        shell = True)

while True:
    clients: list[Client] = []
    if "clients" in ssh_data:
        if ssh_data["clients"]:
            clients = sorted(clients_data_to_client(ssh_data["clients"]),
                             key = lambda c: c.host)
            print_clients(clients)
        else:
            print("No clients found")
    else:
        break
    print("Commands: connect, add, delete, exit")
    user_input: str = input("-> ")
    if user_input == "exit":
        break
    if user_input.lower().startswith("add"):
        new_client: Client = create_client_cli()
        ssh_data["clients"].append(new_client.__dict__)
        dict_to_json(ssh_data,
                     data_path)
        encrypt_data(data_path,
                     decrypt_key)
    if user_input.lower().startswith("connect") and clients:
        input_list: list[str] = user_input.split(" ")
        client_id = input("Client ID: ") if len(input_list) == 1 else input_list[1]
        try:
            client_id = int(client_id)
        except ValueError as e:
            print("Please provide a valid client ID")
            sleep(2)
            continue
        if client_id > 0 and client_id <= len(clients):
            ssh_connect(clients[client_id - 1])
        else:
            print("Invalid client ID")
            sleep(2)
    if user_input.lower().startswith("delete"):
        input_list: list[str] = user_input.split(" ")
        client_id = input("Client ID: ") if len(input_list) == 1 else input_list[1]
        try:
            client_id = int(client_id)
        except ValueError as e:
            print("Please provide a valid client ID")
            sleep(2)
            continue
        if client_id > 0 and client_id <= len(clients):
            client_to_del = clients[client_id - 1]
            confirm: str = input(f"Delete '{client_to_del.user}@{client_to_del.host}'? (y/N) ")
            if confirm.lower() == "y":
                ssh_data["clients"].pop(client_id - 1)
                dict_to_json(ssh_data,
                             data_path)
                encrypt_data(data_path,
                             decrypt_key)
