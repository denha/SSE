import os
import subprocess
import mysql.connector
import paramiko
import jks
from cryptography import x509
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
import pyjks

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from jks import print_pem

from user import save_user_public_key, save_user, login, retrieve_public_key


def upload_keystore_to_server(keystore_names):
    # Set the hostname, username, and password for the virtual machine
    hostname = '88.193.189.84'
    username = 'sse'
    password = '#Include<stdio>12345'

    # Set the local file path and remote file path
    local_file_path = current_directory + "\\" + keystore_names + ".jks"
    remote_file_path = "C:/keys/" + keystore_names + ".jks"

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


def dbconnect():
    dbpams = []
    mydb = mysql.connector.connect(
        host="88.193.189.84",
        user="root",
        password="",
        database="pubkeyauth"
    )
    mycursor = mydb.cursor()
    dbpams.append(mycursor)
    dbpams.append(mydb)
    return dbpams


def key_generation(keystore_password, key_password, alias_name, keystore_name):
    # Set the validity of the key
    validity = "365"

    # Set the distinguished name
    dname = "CN=SSE,OU=DENIS,O=DENIS ORG,L=Tampere,S=TA,C=FI"

    # Set the keystore file name
    keystore_file = keystore_name + ".jks"

    # Execute the keytool command to generate the keystore
    #keytool_cmd = f"keytool -genkey -alias {alias_name} -keyalg RSA -keystore {keystore_file} -storepass {keystore_password} -keypass {key_password} -validity {validity} -dname \"{dname}\""
    cmd = "keytool -genkey -alias mykey -keyalg AES -keysize 128 -storetype JKS -keystore mykeystore.jks -storepass mypassword"
    keytool_cmd = f"keytool -genkeypair -alias {alias_name} -keyalg AES -keysize 128 -keystore {keystore_file} -storepass {keystore_password} -keypass {key_password}"
    subprocess.run(cmd, shell=True)


while True:
    # Generate a random symmetric key
    key = "123456789123456"

    # Create a keystore object
    keystore = pyjks.KeyStore.new('jks', [])

    # Add the symmetric key as a SecretKeyEntry
    keystore.add_secret_key_entry('mykey', key, ['all'])

    # Save the keystore to a file
    pyjks.util.save_keystore('mykeystore.jks', keystore, 'mypassword')
    print("yes")
    print("SELECT THE OPTIONS")
    print("1 :  GENERATE KEYSTORE AND PUBLIC AND PRIVATE KEY PAIR")
    print("2 :  GENERATE USER PUBLIC KEY")
    print("3 :  VIEW PUBLIC AND PRIVATE KEYS")
    select_option = input()

    # if user selects generate keystore
    if select_option == "1":
        print("Enter Keystore Name")
        keystore_name = input()
        print("Enter Keystore Password")
        keystore_password = input()
        print("Enter Key Alias")
        key_alias = input()
        print("Enter Key Password")
        key_password = input()
        key_generation(keystore_password, key_password, key_alias, keystore_name)
        print("################## PUBLISH PUBLIC KEY #####################")
        print("1 : YES ")
        print("2 : NO ")
        print("Do you want to publish this key ?")

        is_publish = input()
        if is_publish == "1":
            dbresult = dbconnect()
            current_directory = os.getcwd()
            # print(current_directory+"\\"+keystore_name+".jks")
            keystore = jks.KeyStore.load(current_directory + "\\" + keystore_name + ".jks", keystore_password)
            # public_key = keystore.private_keys[key_alias].cert_chain[0][1]
            cert_chain_bytes = keystore.private_keys[key_alias].cert_chain[0][1]
            cert = x509.load_der_x509_certificate(cert_chain_bytes)
            public_key = cert.public_key()

            pem_public_key = public_key.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )

            # inserting pubkey auth
            sql = "insert into keygen_publickey(key_id,key_data) values(%s,%s)"
            val = [(key_alias, pem_public_key)]
            dbresult[0].executemany(sql, val)
            dbresult[1].commit()
            upload_keystore_to_server(keystore_name)
            print("Key successfully published")
            print("")
        print("################## PUBLIC KEY / KEYSTORE CREATION #####################")
        print("1 : YES ")
        print("2 : NO ")
        key_creation = input()
        if key_creation == "2":
            break
    elif select_option == "2":
        print("#################### USER PUBLIC KEY GENERATION ################")
        print("1 :  GENERATE USER PUBLIC KEY")
        print("2 :  GET USER PRIVATE KEY")
        user_option = input()
        if user_option == "1":
            print("Enter username ")
            username = input()
            print("Enter email")
            email = input()
            print("Enter password")
            password = input()
            print("USER ID IS " + str(save_user_public_key(save_user(username, email, password))))
        elif user_option == "2":
            print("Enter email")
            email = input()
            print("Enter password")
            password = input()
            login(email, password)


    elif select_option == "3":
        print("************************* PRIVATE AND PUBLIC KEYS *********************************")
        print("Enter key alias");
        key_aliaz = input()
        retrieve_public_key(key_aliaz)

