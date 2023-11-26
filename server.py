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

from jks import print_pem

from keygen.keygen import add_files, sending_files, generate_key, search, download_files, decrypt_download_files, \
    view_downloaded_files,abe_gen
from user import save_user_public_key, save_user, login, retrieve_public_key


def upload_keystore_to_server(keystore_names):
    # Set the hostname, username, and password for the virtual machine
    hostname = '88.193.186.97'
    username = 'see'
    password = 'root'

    # Set the local file path and remote file path
    local_file_path = current_directory + "/" + keystore_names + ".jks"
    #remote_file_path = "C:/keys/" + keystore_names + ".jks"
    remote_file_path = "/home/see/keys/" + keystore_names + ".jks"

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


def key_generation(keystore_password, key_password, alias_name, keystore_name):
    # Set the validity of the key
    validity = "365"

    # Set the distinguished name
    dname = "CN=SSE,OU=DENIS,O=DENIS ORG,L=Tampere,S=TA,C=FI"

    # Set the keystore file name
    keystore_file = keystore_name + ".jks"

    # Execute the keytool command to generate the keystore
    keytool_cmd = f"keytool -genkey -alias {alias_name} -keyalg RSA -keystore {keystore_file} -storepass {keystore_password} -keypass {key_password} -validity {validity} -dname \"{dname}\""
    subprocess.run(keytool_cmd, shell=True)


while True:
    print("SELECT THE OPTIONS")
    print("1 :  GENERATE KEYSTORE AND PUBLIC AND PRIVATE KEY PAIR")
    print("2 :  GENERATE USER PUBLIC KEY")
    print("3 :  VIEW PUBLIC AND PRIVATE KEYS")
    print("4 :  GENERATE KG & KSKE")
    print("5 :  ENCRYPT FILES")
    print("6 :  UPLOAD FILES")
    print("7 :  SEARCH FILES")
    print("8 :  DOWNLOAD")
    print("9 :  DECRYPT DOWNLOADED FILES")
    print("10 : VIEW DOWNLOADED FILES")

    select_option = input()

    # if user selects generate keystore
    if select_option == "1":
        print("1: ABE public and private key gen")
        print("2: OTHER Public key Gen")
        secondOption = input()
        if(secondOption == "1"):
            abe_gen()
            print("ABE keys are generated successfully")
        else:
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
                keystore = jks.KeyStore.load(current_directory + "/" + keystore_name + ".jks", keystore_password)
                # public_key = keystore.private_keys[key_alias].cert_chain[0][1]
                cert_chain_bytes = keystore.private_keys[key_alias].cert_chain[0][1]
                cert = x509.load_der_x509_certificate(cert_chain_bytes)
                public_key = cert.public_key()
                pem_public_key = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
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
        print(retrieve_public_key(key_aliaz))
    elif select_option == "4":
        generate_key()
        print("Key Successfully generated")

    elif select_option == "5":
        print("Enter the path to the location of the files")
        folder_path = input()
        if not os.path.isdir(folder_path):
            print("Invalid folder path")
            exit()
        file_list = folder_path
        add_files(file_list)
        print("Files Successfully encrypted")
    elif select_option == "6":
        sending_files()
        print("Files Successfully uploaded")
    elif select_option == "7":
        print("Enter the keyword")
        keyword = input()
        start_time = time.time()
        search(keyword)
        exec_time = float(time.time() - start_time)
        print("Time Take to Search is " + str(exec_time))
        print("\n")
    elif select_option == "8":
        print("Enter the file ID to download")
        file_id = input()
        download_files(file_id)
    elif select_option == "9":
        print("Enter the file ID to Decrypt")
        file_id = input()
        decrypt_download_files(file_id)
    elif select_option == "10":
        print("Enter the file ID to View")
        file_id = input()
        view_downloaded_files(file_id)
