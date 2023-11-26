import os
import subprocess
import uuid
import zipfile

import jks
from cryptography import x509
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import keyring
import base64
import hmac
import pickle
import hashlib
from connections import dbconnect
from data import response
from keygen.keygen import *
from keygen.models import PublicKey
#from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
#from authapp.crypto import encrypt_aes, encrypt_rsa, decrypt_rsa, encrypt_rsa_chunked, decrypt_rsa_chunked, \
#    encrypt_aes_file, iprf_aes, decrypt_aes, decrypt_aes_file
from user import retrieve_public_key
from authapp.models import User
from authapp.crypto import *
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.adapters.abenc_adapt_hybrid import HybridABEnc
from charm.core.engine.util import objectToBytes, bytesToObject

def gen_pub_pri_key(request):
    try:
        validity = request['validity']
        dname = f"CN={request['cname']},OU={request['ounit']},O={request['organ']},L={request['location']},S={request['state']},C={request['country']}"
        keystore_password = "123456"
        # Set the keystore file name
        keystore_file = request['keystore_name'] + ".jks"
        alias_name = ""
        if request['keystore_name'] == 'CSP':
            alias_name = 'CSP'
        elif request['keystore_name'] == 'TA':
            alias_name = "TA"
        elif request['keystore_name'] == 'DELAUTH':
            alias_name = "DELAUTH"

        # Execute the keytool command to generate the keystore
        keytool_cmd = f"keytool -genkey -alias {alias_name} -keyalg RSA -keystore {keystore_file} -storepass {keystore_password} -keypass {keystore_password} -validity {validity} -dname \"{dname}\""
        subprocess.run(keytool_cmd, shell=True)
        public = PublicKey(id=uuid.uuid4(), cname=request['cname'], ounit=request['ounit'], organ=request['organ'],
                           location=request['location'],
                           state=request['state'], country=request['country'], validity=validity
                           )
        public.save();

        data = PublicKey.objects.values('id', 'cname', 'ounit', 'organ', 'location', 'state', 'country',
                                        'validity').get(
            id=public.id)
        return response("Keys generated", True, data)
    except Exception as e:
        print(e)


def show_pub_key(alias):
    try:
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
        # return user[2].decode()
        return response("success", True, user[2].decode())

    except Exception as e:
        print(e)


def encrypt_files(location, dataowner, files):
    try:
        add_files(location, dataowner, files)
        return response("success", True)
    except Exception as e:
        print(e)


def upload_files(data_owner, files):
    try:
        selected_files = [];
        for file in files:
            if file['checked']:
                selected_files.append(file['name'])
        sending_files(data_owner, selected_files)
        return response("success", True)
    except Exception as e:
        print(e)


def search_files(word, data_owner,key,user_id):
    try:
        if get_cached_kske(user_id):
            keys = get_cached_kske(user_id)
        else:
            keys = get_kske(data_owner, user_id)
            set_cached_kske(user_id, keys)

        if  keys:
            results = search(word, data_owner)
        else:
            results ={'data':{"status":False}}

        return response("success", True, results)
    except Exception as e:
        print(e)


def download_file(file_id):
    try:
        ssh_conn = ssh_connection()
        download_dir = "/usr/local/src/charm-dev/SSEDownloads"
        remote_file_path = "/home/delauth/files/" + file_id
        local_file_path = os.path.join(download_dir, os.path.basename(remote_file_path))
        ssh_conn['sftp_client'].get(remote_file_path, local_file_path)

        # reading file
        file_path = "/usr/local/src/charm-dev/SSEDownloads/" + file_id
        file = open(file_path, "rb")
        content = file.read()
        file.close()

        # Process the file content
        results = base64.b64encode(content).decode('utf-8')
        return response("success", True, results)
    except Exception as e:
        print(e)


def decrypt_file(file_id, owner,user_id):
    try:
        if get_cached_kske(user_id):
            keys = get_cached_kske(user_id)
        else:
            keys = get_kske(data_owner, user_id)
            set_cached_kske(user_id, keys)
        status = False
        message = "success"
        if keys:
            ssh_conn = ssh_connection()
            download_dir = "/usr/local/src/charm-dev/SSEDownloads"
            remote_file_path = "/home/delauth/files/" + file_id
            local_file_path = os.path.join(download_dir, os.path.basename(remote_file_path))
            ssh_conn['sftp_client'].get(remote_file_path, local_file_path)

            print("Downloaded",retrieve_key("KSKE", owner))
            results = decrypt_aes_file(file_id, keys, download_dir, "", True)
            status = True
            message ="success"
        else:
            status = False
            message = "incorrect password"
            results = ""
        return response(message, status, results)
    except Exception as e:
        print(e)


def data_owner():
    try:
        results = fetch_data_owner()
        return response("success", True, results)
    except Exception as e:
        print(e)


def publish_public_key(id):
    try:
        """keystore_name = "CSP"
        current_directory = os.getcwd()
        keystore = jks.KeyStore.load(current_directory + "\\" + keystore_name + ".jks", "123456")
        # public_key = keystore.private_keys[key_alias].cert_chain[0][1]
        cert_chain_bytes = keystore.private_keys['csp'].cert_chain[0][1]
        cert = x509.load_der_x509_certificate(cert_chain_bytes)
        public_key = cert.public_key()

        pem_public_key = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        )
        public = PublicKey.objects.get(id=id)
        public.key_id = 'dataowner'"""


    except Exception as e:
        print(e)


def gen_kg_kske(key, data_owner):
    try:
        service_name = "SSEDATAOWNER" + str(data_owner)
        generated_key = ""
        if key == "KG":
            generated_key = generate_kg()
            keyring.set_password(service_name, "KG", generated_key)
        elif key == "KSKE":
            generated_key = generate_kske()
            keyring.set_password(service_name, "KSKE", generated_key)
        return response("success", True, generated_key)

    except Exception as e:
        print(e)


def retrieve_data_owner_key_dec(keys, dataowner):
    try:
        key = retrieve_key(keys, dataowner)
        return response("success", True, key)
    except Exception as e:
        print(e)


def retrieve_data_owner_key(keys, dataowner):
    try:
        service_name = "SSEDATAOWNER" + str(dataowner)
        key = ""
        if keys == "KG":
            key = keyring.get_password(service_name, "KG")
        elif keys == "KSKE":
            key = keyring.get_password(service_name, "KSKE")
        return response("success", True, key)
    except Exception as e:
        print(e)


def select_files(path):
    try:
        path_selected = "C:\\" + path;
        os.chdir(path_selected)
        file_list = os.listdir(path_selected)
        selected_file = []
        file_id = 1
        for file_name in file_list:
            if file_name.endswith('.txt'):
                selected_file.append({'name': file_name, 'id': file_id})
                file_id = file_id + 1
        return response("success", True, selected_file)
    except Exception as e:
        print(e)


def generate_kg():
    s = 'some random string'
    lambda_value = 128

    salt = os.urandom(16)
    hash_function = hashlib.sha256
    KG = hmac.new(salt, s.encode(), hash_function).digest()

    # Derive a key of length lambda_value from KG using HKDF
    hkdf = HKDF(
        algorithm=SHA256(),
        length=lambda_value // 8,
        salt=salt,
        info=b'KG',
        backend=default_backend()
    )
    derived_key = hkdf.derive(KG)

    return base64.b64encode(derived_key).decode('utf-8')


def generate_kske():
    # Generate a random key for symmetric encryption using AES-256
    key = os.urandom(32)
    lambda_value = 256

    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    derived_key = kdf.derive(key)

    # Create a new instance of the AES cipher using the derived key
    cipher = AESGCM(derived_key)

    nonce = os.urandom(16)
    KSKE = cipher.encrypt(nonce, str(lambda_value).encode(), None)
    return base64.b64encode(KSKE).decode('utf-8')[:24]


def add_files(folder_dic, dataowner, selected_files):
    path = "C:\\" + folder_dic;
    os.chdir(path)
    list_of_address_keyword = []
    list_of_val_key_word = []
    list_of_cipher_file_id = []
    list_of_cipher_text = []
    list_of_no_of_files = []
    list_of_no_of_search = []
    list_of_hashed_keyword = []

    # Count the occurrences of each word
    word_counts = {}
    map = {}
    word_list = []
    dict_words = []

    count_no_of_file = 1
    cipher_file_id = 0
    for file in os.listdir():
        # Check whether file is in text format or not
        if file.endswith(".txt"):
            if file in selected_files:
                with open(file, 'r') as f:
                    for word in f.read().split():
                        found_dicts = [d for d in word_list if d["word"] == word and d['filename'] == f.name]
                        if not found_dicts:
                            distinct_words = {"word": word, "filename": f.name, "file_id": count_no_of_file}
                            word_list.append(distinct_words)
                    key = os.urandom(32)
                    output_folder = 'encrypted_files'
                    list_of_cipher_text.append(f.name)
                    cipher_file_name = encrypt_aes(f.name, retrieve_data_owner_key("KSKE", dataowner)['data'], True)

                    os.makedirs(output_folder, exist_ok=True)
                    encrypt_aes_file(f.name, retrieve_data_owner_key("KSKE", dataowner)['data'], output_folder, f.name)
                    count_no_of_file = count_no_of_file + 1

    unique_words = set()
    for d in word_list:
        unique_words.add(d['word'])

    unique_words_sorted = sorted(list(unique_words))

    for unique_word in unique_words_sorted:

        for i, d in enumerate(word_list):
            if d['word'] == unique_word:
                dict = {'word': d['word'], 'filename': d['filename'], 'file_id': d['filename']}
                dict_words.append(dict)

    word_count = {}

    # Loop through dictionaries in the list and increment the count for each word
    for d in dict_words:
        word = d['word']
        if word in word_count:
            word_count[word] += 1
        else:
            word_count[word] = 1

    for word, count in sorted(word_count.items()):

        no_of_file = count + 1
        no_of_search = 0
        key_word_hashed = hash256(word)
        list_of_hashed_keyword.append(key_word_hashed)
        message = key_word_hashed + str(no_of_search)

        list_of_no_of_files.append(str(no_of_file))
        list_of_no_of_search.append(str(no_of_search))

        key_word_encrypted = iprf_aes(message, retrieve_data_owner_key("KG", dataowner)['data'])
        address_keyword = hash256(key_word_encrypted + str(no_of_file))

        found_dicts = [d for d in dict_words if d["word"] == word]
        for found_word in found_dicts:
            val_key_word = encrypt_aes(str(found_word['file_id']) + str(count),
                                       retrieve_data_owner_key("KSKE", dataowner)['data'])

            list_of_address_keyword.append(address_keyword)
            list_of_val_key_word.append(val_key_word)

            cipher_file_id = cipher_file_id + 1
            # list_of_cipher_file_id.append(
            #   encrypt_aes(str(found_word['file_id']), retrieve_data_owner_key("KSKE"), True))
            list_of_cipher_file_id.append(str(found_word['file_id']) + '.enc')

    map['address'] = list_of_address_keyword
    map['val_key'] = list_of_val_key_word

    vals = {'map': map, 'no_of_files': list_of_no_of_files, 'no_of_search': list_of_no_of_search,
            'cipher': list_of_cipher_text, 'cipher_id': list_of_cipher_file_id, 'enc_dir': path,
            'h_keyword': list_of_hashed_keyword, 'path': folder_dic, 'no_selected_files': len(selected_files)}
    current_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(current_dir)

    with open('temp_files.pkl', 'wb') as f:
        pickle.dump(vals, f)


def sending_files(data_owner, selected_files):
    c = {}
    all_map = {}
    data_dict = {}
    os.chdir("C:\Symetric Enc\SYSSE\\keygen")
    # os.chdir("keygen")
    with open('temp_files.pkl', 'rb') as f:
        loaded_variable = pickle.load(f)
        if len(selected_files)<loaded_variable['no_selected_files']:
            add_files(loaded_variable['path'], data_owner, selected_files)

    with open('temp_files.pkl', 'rb') as f:
        loaded_variable = pickle.load(f)
        path_to_enc_files = loaded_variable['enc_dir'] + '\\' + "encrypted_files"
        dest_zipped_location = loaded_variable['enc_dir']

        zip_obj = zipfile.ZipFile(dest_zipped_location + '\zipped_folder.zip', 'w', zipfile.ZIP_DEFLATED)
        for root, dirs, files in os.walk(path_to_enc_files):
            for file in files:
                zip_obj.write(os.path.join(root, file))

        zip_obj.close()
        all_map['map'] = loaded_variable['map']
        all_map['cid'] = loaded_variable['cipher_id']

        csp_recieves_files(all_map, data_owner)
        # uploading enc files
        upload_cipher(dest_zipped_location)

    # sending no.files and no.searches to TA
    string_of_no_of_files = ','.join(loaded_variable['no_of_files'])
    string_of_no_of_search = ','.join(loaded_variable['no_of_search'])
    string_of_hashed_keyword = ','.join(loaded_variable['h_keyword'])

    encrypted_no_of_file = encrypt_rsa_chunked(string_of_no_of_files, retrieve_public_key("TA"))
    encrypted_no_of_search = encrypt_rsa_chunked(string_of_no_of_search, retrieve_public_key("TA"))
    encrypted_hashed_keyword = encrypt_rsa_chunked(string_of_hashed_keyword, retrieve_public_key("TA"))
    ta_receives_files(encrypted_no_of_file, encrypted_no_of_search, encrypted_hashed_keyword, data_owner)

    # send KSKE to delauth
    send_keys("DELAUTH", retrieve_data_owner_key("KSKE", data_owner)['data'], data_owner)

    # send KG to Ta
    send_keys("TA", retrieve_data_owner_key("KG", data_owner)['data'], data_owner)

def get_kske(owner,user_id):
    try:
        keystore = redis_key_store_connection()
        encrypted_sk = keystore.hgetall('user' + str(user_id))
        decrypted_sk = decrypt_rsa_chunked(encrypted_sk['KEY'], retrieve_private_key("user" + str(user_id)))
        group = PairingGroup('SS512')
        sk = bytesToObject(decrypted_sk.encode('utf-8'), group)
        mpk = bytesToObject(retrieve_public_key("ta-abe").encode('utf-8'), group)
        cipher_text = bytesToObject(retrieve_key("policy" + str(owner)).encode('utf-8'), group)
        kske = abe_decrypt(mpk, sk, cipher_text).decode()
        return kske
    except Exception as e:
        print(e)
        return False
