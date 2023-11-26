import hashlib

import bcrypt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization
import mysql.connector
from authapp.crypto import *
from keygen.models import PublicKey
from authapp.models import User
import os
import subprocess
import mysql.connector
import paramiko
import jks
from cryptography import x509
import time
import requests
#from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from jks import print_pem
from keygen.keygen import  *

def generate_private_key(password):
    # Generate a salt and derive an encryption key from the password
    salt = os.urandom(16)
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1, backend=default_backend())
    key = kdf.derive(password)

    # Hash the encryption key to get a fixed-length key for the RSA key generation
    key_hash = hashlib.sha256(key).digest()

    # Generate a new private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())

    # Encrypt the private key using the encryption key
    encrypted_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(key),
    )
    # 0 for private key 1 for encrypted key
    return private_key, encrypted_key

def dbconnect():
    dbpams = []
    config ={
        'host':"88.193.186.97",
        'user':"sse",
        'password':"root",
        'database':"pubkeyauth",
        'ssl_disabled':True
    }
    """mydb = mysql.connector.connect(
        host="88.193.186.97",
        user="sse",
        password="root",
        database="pubkeyauth"
    )"""
    mydb = mysql.connector.connect(**config)
    mycursor = mydb.cursor()
    dbpams.append(mycursor)
    dbpams.append(mydb)
    return dbpams

def save_user_public_key(key_store_password,user):
    # Set the validity of the key
    validity = "365"
    # Set the distinguished name
    dname = "CN=SSE,OU=DENIS,O=DENIS ORG,L=Tampere,S=TA,C=FI"

    # Set the keystore file name
    keystore_file = user + ".jks"
    #key_store_password="123456"
    # Execute the keytool command to generate the keystore
    keytool_cmd = f"keytool -genkey -alias {user} -keyalg RSA -keystore {keystore_file} -storepass {key_store_password} -keypass {key_store_password} -validity {validity} -dname \"{dname}\""
    subprocess.run(keytool_cmd, shell=True)

    hostname = '88.193.186.97'
    username = 'see'
    password = 'root'

    current_directory = "/usr/local/src/charm-dev"
    """ save public key to pubkey auth"""
    keystore = jks.KeyStore.load(current_directory + "/" + user + ".jks", key_store_password)

    # public_key = keystore.private_keys[key_alias].cert_chain[0][1]
    cert_chain_bytes = keystore.private_keys[user].cert_chain[0][1]
    cert = x509.load_der_x509_certificate(cert_chain_bytes)
    public_key = cert.public_key()
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # inserting pubkey auth
    dbresult = dbconnect()
    sql = "insert into keygen_publickey(key_id,key_data) values(%s,%s)"
    val = [(user, pem_public_key)]
    dbresult[0].executemany(sql, val)
    dbresult[1].commit()

    """upload the keystore to public repostory """
    # Set the local file path and remote file path
    local_file_path = current_directory + "/" + user + ".jks"
    #remote_file_path = "C:/keys/" + keystore_names + ".jks"
    remote_file_path = "/home/see/keys/" + user + ".jks"

    # Create an SSH client and connect to the virtual machine
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname=hostname, username=username, password=password)

    # Open a SFTP session and upload the file
    sftp_client = ssh_client.open_sftp()
    sftp_client.put(local_file_path, remote_file_path)

    # Close the SFTP session and the SSH client
    sftp_client.close()
    ssh_client.close()


def user_log_in(email, password):
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # check if user has supplied in right password and email
        user = User.objects.filter(email=email).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            # user has supplied the correct email and password
            #private_key = generate_private_key(password.encode())[1]
            #encrypted_key = encrypt_aes(private_key.decode('utf-8'), user.password[:16])
            data = {'email': user.email, 'user_id': user.id,
                     'role': user.role}

            return data

        else:
            return False
    except Exception as e:
        return e


def user_private_key(user_id, encryted_key):
    try:
        # fetching hashed password to decrypt the private key
        user = User.objects.filter(id=user_id).first()
        return decrypt_aes(encryted_key, user.password[:16])

    except Exception as e:
        return e
