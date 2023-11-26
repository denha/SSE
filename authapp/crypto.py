import hashlib
import io
import os

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
import base64

from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_private_key
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import padding as paddings
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.adapters.abenc_adapt_hybrid import HybridABEnc
from charm.core.engine.util import objectToBytes, bytesToObject


def key_gen_abe():
    group = PairingGroup('SS512')
    cpabe = CPabe_BSW07(group)
    hyb_abe = HybridABEnc(cpabe,group)
    (master_public_key, master_key) = hyb_abe.setup()
    return master_public_key,master_key,group

def secret_key_gen(mpk,msk,attributes):
    group = PairingGroup('SS512')
    cpabe = CPabe_BSW07(group)
    hyb_abe = HybridABEnc(cpabe, group)
    master_public_key = bytesToObject(mpk,group)
    master_secret_key = bytesToObject(msk,group)
    return hyb_abe.keygen(master_public_key, master_secret_key, [attributes])

def abe_decrypt(mpk,sk,cipher_text):
    group = PairingGroup('SS512')
    cpabe = CPabe_BSW07(group)
    hyb_abe = HybridABEnc(cpabe, group)
    return hyb_abe.decrypt(mpk, sk, cipher_text)

def encrypt_aes(message, key_param, deterministic=False):
    """key = key_param.encode('utf-8')
    cipher = AES.new(key, AES.MODE_CBC)
    padded_message = pad(message.encode('utf-8'), AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    encrypted_message = base64.b64encode(encrypted_message).decode('utf-8')
    return iv + ':' + encrypted_message"""
    key = key_param.encode('utf-8')
    decode_format = ''
    if deterministic:
        iv = b'\x00' * AES.block_size  # Use a fixed IV for determinism
        decode_format = 'utf-16le'
    else:
        cipher = AES.new(key, AES.MODE_CBC)
        iv = cipher.iv
        decode_format = 'utf-8'
    # cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode('utf-8'), AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)
    iv = base64.b64encode(iv).decode('utf-8')

    encrypted_message = base64.b64encode(encrypted_message).decode(decode_format)

    return encrypted_message


def decrypt_aes(ciphertext, key_param, is_file_naming=False):
    key = key_param.encode('utf-8')

    if is_file_naming:
        ciphertext = ciphertext.encode('utf-16le')
    ciphertext = base64.b64decode(ciphertext)
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return decrypted_message.decode('utf-8')


def encrypt_rsa(data, public_key_str):
    public_key_bytes = public_key_str.encode('utf-8')
    public_key = serialization.load_pem_public_key(public_key_bytes)
    ciphertext = public_key.encrypt(
        data.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return base64.b64encode(ciphertext).decode('utf-8')


def decrypt_rsa(ciphertext, private_key_str):
    ciphertext = base64.b64decode(ciphertext)
    private_key = load_der_private_key(private_key_str, password=None)
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode()


def encrypt_rsa_chunked(data, public_key_str, chunk_size=128):
    public_key_bytes = public_key_str.encode('utf-8')
    public_key = serialization.load_pem_public_key(public_key_bytes)

    data += ' '
    # Divide the data into chunks
    chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]

    # Encrypt each chunk separately
    encrypted_chunks = []
    for chunk in chunks:
        ciphertext = public_key.encrypt(
            chunk.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_chunks.append(ciphertext)

    # Concatenate the encrypted chunks back together
    encrypted_data = b"".join(encrypted_chunks)
    return base64.b64encode(encrypted_data).decode('utf-8')


def decrypt_rsa_chunked(ciphertext, private_key_str, chunksize=256):
    """ciphertext = base64.b64decode(ciphertext)
    private_key = load_der_private_key(private_key_str, password=None)
    block_size = private_key.key_size // 8
    assert chunksize % 8 == 0, "chunksize must be a multiple of 8"

    blocks = []
    for i in range(0, len(ciphertext), chunksize):
        block = ciphertext[i:i + chunksize]
        decrypted_block = private_key.decrypt(
            block,
            OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        blocks.append(decrypted_block)

    data = b''.join(blocks)

    # Remove padding
    pad_len = data[-1]
    pad_idx = -pad_len
    data = data[:pad_idx]

    return data.decode()"""
    ciphertext = base64.b64decode(ciphertext)
    private_key = load_der_private_key(private_key_str, password=None)
    block_size = private_key.key_size // 8
    assert chunksize % 8 == 0, "chunksize must be a multiple of 8"

    blocks = []
    for i in range(0, len(ciphertext), chunksize):
        block = ciphertext[i:i + chunksize]
        decrypted_block = private_key.decrypt(
            block,
            OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        blocks.append(decrypted_block)

    data = b''.join(blocks)

    # Find the index of the first null byte from the end
    pad_idx = data.find(b'\x00', -1)

    # Remove padding
    data = data[:pad_idx]

    return data.decode()


"""def encrypt_aes_file(filename, key, output_folder, cipher_file_name):
    chunk_size = 64 * 1024
    output_filename = os.path.join(output_folder, os.path.basename(cipher_file_name))
    # output_filename = os.path.join(output_folder, os.path.basename(filename) + '.enc')
    iv = os.urandom(16)
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    with open(filename, 'rb') as input_file, open(output_filename, 'wb') as output_file:
        output_file.write(iv)
        while True:
            chunk = input_file.read(chunk_size)
            if len(chunk) == 0:
                break
            padded_chunk = padder.update(chunk) + padder.finalize()
            encrypted_chunk = encryptor.update(padded_chunk)
            output_file.write(encrypted_chunk)
        output_file.write(encryptor.finalize())


def decrypt_aes_file(cipher_filename, key, output_folder, decrypted_file_name):
    chunk_size = 64 * 1024
    decrypted_filename = os.path.join(output_folder, decrypted_file_name)
    encrypted_file_location = os.path.join(output_folder, cipher_filename)
    key_bytes = key.encode('utf-8')  # Convert the key string to bytes
    with open(encrypted_file_location, 'rb') as input_file, open(decrypted_filename, 'wb') as output_file:
        iv = input_file.read(16)
        decryptor = Cipher(algorithms.AES(key_bytes), modes.CBC(iv)).decryptor()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        while True:
            chunk = input_file.read(chunk_size)
            if len(chunk) == 0:
                break
            decrypted_chunk = decryptor.update(chunk) + decryptor.finalize()
            try:
                unpadded_chunk = unpadder.update(decrypted_chunk) + unpadder.finalize()
            except ValueError:
                # Handle potential padding errors
                unpadded_chunk = decrypted_chunk
            output_file.write(unpadded_chunk)"""

"""def decrypt_aes_file(cipher_filename, key, output_folder, decrypted_file):
    chunk_size = 64 * 1024
    decrypted_filename = os.path.join(output_folder, decrypted_file)
    key_bytes = key.encode('utf-8')
    encrypted_file_location = os.path.join(output_folder, cipher_filename)

    with open(encrypted_file_location, 'rb') as input_file, open(decrypted_filename, 'wb') as output_file:
        iv = input_file.read(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()

        while True:
            chunk = input_file.read(chunk_size)
            if len(chunk) == 0:
                break
            decrypted_chunk = decryptor.update(chunk)
            unpadded_chunk = unpadder.update(decrypted_chunk)

            # Check if the last chunk is being processed and apply finalization
            if len(chunk) < chunk_size:
                decrypted_chunk = decryptor.finalize()
                unpadded_chunk += unpadder.update(decrypted_chunk)
                unpadded_chunk += unpadder.finalize()

            output_file.write(unpadded_chunk)"""


# Usage example


def iprf_aes(message, key_param):
    key = key_param.encode('utf-8')
    hashed_key = hashlib.sha256(key).digest()

    cipher = AES.new(hashed_key, AES.MODE_ECB)
    padded_message = pad(message.encode('utf-8'), AES.block_size)
    encrypted_message = cipher.encrypt(padded_message)

    encoded_message = base64.b64encode(encrypted_message).decode('utf-8')

    return encoded_message


"""def encrypt_aes_file(filename, key, output_folder, cipher_file_name):
    chunk_size = 64 * 1024
    output_filename = os.path.join(output_folder, os.path.basename(cipher_file_name))
    iv = os.urandom(16)

    key_bytes = key  # Convert key to bytes

    encryptor = Cipher(algorithms.AES(key_bytes), modes.CBC(iv)).encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()

    with open(filename, 'rb') as input_file, open(output_filename, 'wb') as output_file:
        output_file.write(iv)
        while True:
            chunk = input_file.read(chunk_size)
            if len(chunk) == 0:
                break
            padded_chunk = padder.update(chunk) + padder.finalize()
            encrypted_chunk = encryptor.update(padded_chunk)
            output_file.write(encrypted_chunk)
        output_file.write(encryptor.finalize())



def decrypt_aes_file(cipher_filename, key, output_folder, decrypted_file):
    chunk_size = 64 * 1024
    decrypted_filename = os.path.join(output_folder, decrypted_file)
    key_bytes = key.encode('utf-8')  # Convert key to bytes

    encrypted_file_location = os.path.join(output_folder, cipher_filename)

    with open(encrypted_file_location, 'rb') as input_file, open(decrypted_filename, 'wb') as output_file:
        iv = input_file.read(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()

        # Read the cipher text and decode from base64
        cipher_text = input_file.read()
        decoded_cipher_text = base64.b64decode(cipher_text)

        # Decrypt and write the plain text
        decrypted_text = decryptor.update(decoded_cipher_text) + decryptor.finalize()
        try:
            unpadded_text = unpadder.update(decrypted_text) + unpadder.finalize()
        except ValueError:
            # Handle potential padding errors
            unpadded_text = decrypted_text
        output_file.write(unpadded_text)

"""


def encrypt_aes_file(filename, key, output_folder, cipher_file_name):
    chunk_size = 64 * 1024
    cipher_file_name = cipher_file_name + '.enc'
    output_filename = os.path.join(output_folder, os.path.basename(cipher_file_name))
    iv = os.urandom(16)

    key_bytes = key.encode('utf-8')  # Convert key to bytes

    encryptor = Cipher(algorithms.AES(key_bytes), modes.CBC(iv)).encryptor()
    padder = paddings.PKCS7(algorithms.AES.block_size).padder()

    with open(filename, 'rb') as input_file, open(output_filename, 'wb') as output_file:
        output_file.write(iv)
        while True:
            chunk = input_file.read(chunk_size)
            if len(chunk) == 0:
                break
            padded_chunk = padder.update(chunk) + padder.finalize()
            encrypted_chunk = encryptor.update(padded_chunk)
            output_file.write(encrypted_chunk)
        output_file.write(encryptor.finalize())


def encrypt_aes_file_sync(filename, key, output_folder, cipher_file_name, file_content):
    chunk_size = 128 * 1024
    cipher_file_name = filename + '.enc'
    output_filename = os.path.join(output_folder, os.path.basename(cipher_file_name))
    iv = os.urandom(16)

    key_bytes = key.encode('utf-8')  # Convert key to bytes

    encryptor = Cipher(algorithms.AES(key_bytes), modes.CBC(iv)).encryptor()
    padder = paddings.PKCS7(algorithms.AES.block_size).padder()

    with io.BytesIO(file_content.encode('utf-8')) as input_file, open(output_filename, 'wb') as output_file:
        output_file.write(iv)
        while True:
            chunk = input_file.read(chunk_size)
            if len(chunk) == 0:
                break
            padded_chunk = padder.update(chunk) + padder.finalize()
            encrypted_chunk = encryptor.update(padded_chunk)
            output_file.write(encrypted_chunk)
        output_file.write(encryptor.finalize())


def decrypt_aes_file(cipher_filename, key, output_folder, decrypted_file, variable_output=False):
    chunk_size = 64 * 1024
    decrypted_file = os.path.splitext(decrypted_file)[0]
    decrypted_filename = os.path.join(output_folder, decrypted_file)
    key_bytes = key.encode('utf-8')  # Convert key to bytes
    print("cipher filen", cipher_filename)
    print("key", key)
    print("out", output_folder)
    print("decyrped file", decrypted_file)
    encrypted_file_location = os.path.join(output_folder, cipher_filename)

    if variable_output:
        with open(encrypted_file_location, 'rb') as input_file:
            iv = input_file.read(16)
            cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
            decryptor = cipher.decryptor()
            unpadder = paddings.PKCS7(algorithms.AES.block_size).unpadder()

            decrypted_content = b''
            while True:
                chunk = input_file.read(chunk_size)
                if len(chunk) == 0:
                    break
                decrypted_chunk = decryptor.update(chunk)
                unpadded_chunk = unpadder.update(decrypted_chunk)

                # Check if the last chunk is being processed and apply finalization
                if len(chunk) < chunk_size:
                    decrypted_chunk = decryptor.finalize()
                    unpadded_chunk += unpadder.update(decrypted_chunk)
                    unpadded_chunk += unpadder.finalize()

                decrypted_content += unpadded_chunk
            return decrypted_content.decode('utf-8')

    with open(encrypted_file_location, 'rb') as input_file, open(decrypted_filename, 'wb') as output_file:
        iv = input_file.read(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        unpadder = paddings.PKCS7(algorithms.AES.block_size).unpadder()

        while True:
            chunk = input_file.read(chunk_size)
            if len(chunk) == 0:
                break
            decrypted_chunk = decryptor.update(chunk)
            unpadded_chunk = unpadder.update(decrypted_chunk)

            # Check if the last chunk is being processed and apply finalization
            if len(chunk) < chunk_size:
                decrypted_chunk = decryptor.finalize()
                unpadded_chunk += unpadder.update(decrypted_chunk)
                unpadded_chunk += unpadder.finalize()

            output_file.write(unpadded_chunk)
