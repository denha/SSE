from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from flask import Flask,request,jsonify
from charm.adapters.abenc_adapt_hybrid import HybridABEnc
import pymysql
import json
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.serialization import load_der_private_key, load_pem_private_key
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import padding as paddings
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
import paramiko
import redis
import base64
import hashlib
import os

"""group = PairingGroup('SS512')
cpabe = CPabe_BSW07(group)
msg = group.random(GT)
#print(group.encode("DENIS"))
attributes = ['ONE', 'TWO', 'THREE']
access_policy = '((four or three) and (three or one))'
(master_public_key, master_key) = cpabe.setup()
secret_key = cpabe.keygen(master_public_key, master_key, attributes)
cipher_text = cpabe.encrypt(master_public_key, msg, access_policy)
decrypted_msg = cpabe.decrypt(master_public_key, secret_key, cipher_text)
print(msg == decrypted_msg)"""

def ABE():
    group = PairingGroup('SS512')
    cpabe = CPabe_BSW07(group)
    hyb_abe = HybridABEnc(cpabe,group)
    (master_public_key, master_key) = hyb_abe.setup()
    access_policy = '((four or three) and (two or one))'
    sk = hyb_abe.keygen(master_public_key, master_key, ['ONE', 'TWO', 'THREE'])
    ciphertext = hyb_abe.encrypt(master_public_key, "DENIS", access_policy)
    decrypted_msg = hyb_abe.decrypt(master_public_key, sk, ciphertext)
    print(decrypted_msg)

def encrypt_rsa_chunked(data, public_key_str, chunk_size=128):
    public_key_bytes = public_key_str.encode('utf-8')
    public_key = serialization.load_pem_public_key(public_key_bytes,backend=default_backend())

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

def redis_key_store_connection():
    redis_host = os.environ.get('REDIS_HOST', '84.249.49.8')
    redis_port = os.environ.get('REDIS_PORT', 6379)
    redis_password = os.environ.get('REDIS_PASSWORD', None)
    r = redis.StrictRedis(host=redis_host, port=redis_port, password=redis_password, decode_responses=True)
    return r

def retrieve_private_key(key_id):
    try:
        # Establish an SSH connection to the virtual machine
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect('88.193.161.217', username='see', password='root')
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

        # Close the SSH connection
        ssh.close()
        return private_key
    except Exception as e:
        print("error" + str(e))

app = Flask(__name__)

@app.route('/key-gen', methods=['GET'])
def add_numbers():
    #print(ABE())
    #data = request.get_json()
    group = PairingGroup('SS512')
    cpabe = CPabe_BSW07(group)
    (master_public_key, master_key) = cpabe.setup()
    host ="88.193.174.4"
    user ="sse"
    password ="root"
    db="pubkeyauth"
    mpk = str(master_public_key['g'])+"."+str(master_public_key['g2'])+"."+str(master_public_key['h'])+"."+str(master_public_key['f'])+"."+str(master_public_key['e_gg_alpha'])
    connection = pymysql.connect(host=host,user=user,password=password,database=db)
    cursor = connection.cursor();
    query = "insert into keygen_publickey(key_id,key_data) values (%s,%s)"
    values = ("ta-abe",mpk)
    cursor.execute(query,values)
    connection.commit()

    #encrypt and save public key
    selectQuery ="select * from keygen_publickey where key_id ='ta'"
    cursor.execute(selectQuery)
    results = cursor.fetchall()
    msk = str(master_key['beta'])+"."+str(master_key['g2_alpha'])
    print(encrypt_rsa_chunked(msk,results[0][2].decode()))
    keystore = redis_key_store_connection()
    keystore.set("TA",encrypt_rsa_chunked(msk,results[0][2].decode()))
    if  True:

        return jsonify({'result': 12})
    else:
        return jsonify({'error': 'Missing parameters'}), 400

@app.route('/attributes', methods=['GET'])
def recieve_attributes(): 
    retrieve_private_key("TA")
    return jsonify({'result': retrieve_private_key("TA")})
    pass

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

