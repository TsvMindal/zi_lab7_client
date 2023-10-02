import socket
import pickle
import subprocess

# Константы для путей к файлам
ROOT_KEYPAIR_PATH = 'C:/Users/trudo/PycharmProjects/zi_lab7_client/root_keypair.pem'
ROOT_CERT_PATH = 'C:/Users/trudo/PycharmProjects/zi_lab7_client/root_cert.pem'
PUBLIC_KEY_PATH = 'C:/Users/trudo/PycharmProjects/zi_lab7_client/public_key.pem'
CERT_PUBLIC_KEY_PATH = 'C:/Users/trudo/PycharmProjects/zi_lab7_client/cert_public_key.pem'
FILE_PATH = 'C:/Users/trudo/PycharmProjects/zi_lab7_client/file_to_server.txt'
ENCRYPTED_FILE_PATH = 'C:/Users/trudo/PycharmProjects/zi_lab7_client/encrypted_file.txt'

SERVER_PORT = 3001


def decrypt_file(enc_file_path, output_file_path):
    openssl_command = f'openssl smime -decrypt -binary -in {enc_file_path} -inform DER -inkey {ROOT_KEYPAIR_PATH} -out {output_file_path}'
    subprocess.run(openssl_command, check=True)


def send_file_to_server(local_file_path, SERVER_PORT):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', SERVER_PORT))  # Прямое указание адреса сервера

    with open(local_file_path, 'rb') as file:
        file_content = file.read()

    file_data = pickle.dumps((local_file_path, file_content))
    client_socket.sendall(file_data)

    response = client_socket.recv(1024)
    server_file_name, encrypted_file_content = pickle.loads(response)

    with open(ENCRYPTED_FILE_PATH, 'wb') as file:
        file.write(encrypted_file_content)

    enc_file_path = server_file_name
    decrypt_file(enc_file_path, 'decrypted_file.txt')

    client_socket.close()
    decrypted_file_path = "decrypted_file.txt"

    return decrypted_file_path


def generate_and_compare_public_keys():
    generate_public_key()
    generate_cert_public_key()

    with open(PUBLIC_KEY_PATH, 'r') as public_key_file:
        public_key_content = public_key_file.read()

    with open(CERT_PUBLIC_KEY_PATH, 'r') as cert_public_key_file:
        cert_public_key_content = cert_public_key_file.read()

    return public_key_content == cert_public_key_content


def generate_public_key():
    openssl_command = f'openssl rsa -in {ROOT_KEYPAIR_PATH} -pubout -out {PUBLIC_KEY_PATH}'
    subprocess.run(openssl_command, capture_output=True, text=True)


def generate_cert_public_key():
    openssl_command = f'openssl x509 -in {ROOT_CERT_PATH} -pubkey -noout -out {CERT_PUBLIC_KEY_PATH}'
    subprocess.run(openssl_command, capture_output=True, text=True)


decrypted_file_path = send_file_to_server(FILE_PATH, SERVER_PORT)
print("Расшифрованный файл: ", decrypted_file_path)

if generate_and_compare_public_keys():
    print("Подписи совпадают!")
else:
    print("Подписи не совпадают!")
