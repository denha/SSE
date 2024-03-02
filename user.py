import os

import mysql.connector
import hashlib

import bcrypt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization
import paramiko
import jks


def dbconnect(database):
    dbpams = []
    config ={
        'host':"88.193.186.97",
        'user':"sse",
        'password':"root",
        'database':database,
        'ssl_disabled':True
    }
    mydb = mysql.connector.connect(**config)
    mycursor = mydb.cursor()
    dbpams.append(mycursor)
    dbpams.append(mydb)
    return dbpams


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


def save_user(username, email, password):
    dbresult = dbconnect("sse")
    # inserting pubkey auth
    role = "user"
    sql = "insert into authapp_user(username,email,password,role) values(%s,%s,%s,%s)"
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    val = [(username, email, hashed_password, role)]
    dbresult[0].executemany(sql, val)
    dbresult[1].commit()
    last_row = dbresult[0].lastrowid
    return last_row, password


def save_user_public_key(save_user_func):
    dbresult = dbconnect("pubkeyauth")
    user_id = save_user_func[0]
    password = save_user_func[1]

    private_key = generate_private_key(password.encode())[0]

    # Generate a public key from the private key
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # saving key to pubkey auth
    sql = "insert into keygen_publickey(key_id,key_data,user_id) values(%s,%s,%s)"
    val = [('user', public_key, user_id)]
    dbresult[0].executemany(sql, val)
    dbresult[1].commit()
    return user_id


def login(email, password):
    dbresult = dbconnect("sse")
    # check if user exists
    sql = "SELECT * FROM authapp_user WHERE email = %s"
    val = (email,)
    dbresult[0].execute(sql, val)
    user = dbresult[0].fetchone()
    if user is None:
        print("User does not exist")
    else:
        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            # user has supplied the correct email and password
            private_key = generate_private_key(password.encode())[1]
            print(private_key.decode())


def retrieve_public_key(alias):
    keys = alias.split(",");
    dbresult = dbconnect("pubkeyauth")
    # check if user exists
    if len(keys) == 2:
        sql = "SELECT * FROM keygen_publickey WHERE key_id = %s and user_id= %s"
        val = (keys[0], keys[1])
    elif len(keys) == 1:
        sql = "SELECT * FROM keygen_publickey WHERE key_id = %s "
        val = (alias,)
    dbresult[0].execute(sql, val)
    user = dbresult[0].fetchone()
    # print(user[2].decode())
    return user[2].decode()


def retrieve_private_key(key_id):
    try:
        # Establish an SSH connection to the virtual machine
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect('88.193.186.97', username='see', password='root')
        private_key = ""
        # Download the keystore file using SFTP
        if key_id == 'DELAUTH':
            sftp = ssh.open_sftp()
            sftp.get('/home/see/keys/DELAUTH.jks', 'DELAUTH.jks')
            sftp.close()

            keystore_del_auth = jks.KeyStore.load('DELAUTH.jks', '123456')
            private_key = keystore_del_auth.private_keys['delauth'].pkey

        if key_id == 'CSP':
            sftp = ssh.open_sftp()
            sftp.get('/home/see/keys/CSP.jks', 'CSP.jks')
            sftp.close()

            keystore_del_auth = jks.KeyStore.load('CSP.jks', '123456')
            private_key = keystore_del_auth.private_keys['csp'].pkey

        if key_id == 'TA':
            sftp = ssh.open_sftp()
            sftp.get('/home/see/keys/TA.jks', 'TA.jks')
            sftp.close()

            keystore_del_auth = jks.KeyStore.load('TA.jks', '123456')
            private_key = keystore_del_auth.private_keys['ta'].pkey
        if key_id.find("user")!=-1:
            sftp = ssh.open_sftp()
            sftp.get('/home/see/keys/'+key_id+'.jks', key_id+'.jks')
            sftp.close()
            dbresult = dbconnect("sse")
            sql = "SELECT * from authapp_user WHERE id = %s "
            val = (key_id[4:],)
            dbresult[0].execute(sql, val)
            user_ = dbresult[0].fetchone()
            password =str(user_[3][:6]).replace('$','X')
            keystore_del_auth = jks.KeyStore.load(key_id+'.jks', password)
            private_key = keystore_del_auth.private_keys[key_id].pkey



        # Close the SSH connection
        ssh.close()
        return private_key
    except Exception as e:
        print("error" + str(e))
    """dbresult = dbconnect("pubkeyauth")
    # check if user exists
    if len(keys) == 2:
        sql = "SELECT * FROM keygen_publickey WHERE key_id = %s and user_id= %s"
        val = (keys[0], keys[1])"""