import base64
import pickle
import hmac
import hashlib
import zipfile
import socket
import time

import mysql
import paramiko
from cryptography.hazmat.primitives.ciphers import algorithms, Cipher, modes
# from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import keyring
import redis
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.adapters.abenc_adapt_hybrid import HybridABEnc
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07


from authapp.crypto import encrypt_aes, encrypt_rsa, decrypt_rsa, encrypt_rsa_chunked, decrypt_rsa_chunked, \
    encrypt_aes_file, iprf_aes, decrypt_aes, decrypt_aes_file,key_gen_abe

from user import retrieve_public_key, retrieve_private_key, dbconnect as connection


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


def generate_key(dataowner=0):
    # KG[0] ELSKE [1]
    service_name = "SSEDATAOWNER" + str(dataowner)

    # data owner keys to the current machine keyring
    keyring.set_password(service_name, "KG", generate_kg())
    keyring.set_password(service_name, "KSKE", generate_kske())

def get_cached_kske(user):
    service_name = "SSEUSER" + str(user)
    if keyring.get_password(service_name, "KSKE_KEY"):
        return keyring.get_password(service_name, "KSKE_KEY")

def set_cached_kske(user,key):
    service_name = "SSEUSER" + str(user)
    keyring.set_password(service_name, "KSKE_KEY", key)
def ssh_connection():
    # Set the hostname, username, and password for the virtual machine
    hostname = '88.193.177.146'
    username = 'delauth'
    password = 'root'

    # Create an SSH client and connect to the virtual machine
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname=hostname, username=username, password=password)

    sftp_client = ssh_client.open_sftp()
    return {'sftp_client': sftp_client, 'ssh_client': ssh_client}


def upload_cipher(location):
    try:
        print("here 2")
        print("location",location)
        ssh_conn = ssh_connection()
        # Set the local file path and remote file path
        # remote_file_path = "C:/files/zipped_folder.zip"
        remote_file_path = "/home/delauth/files/zipped_folder.zip"
        path = "/home/delauth/files/"
        ssh_conn['sftp_client'].put("/usr/local/src/charm-dev/encrypted_files"+ "/zipped_folder.zip", remote_file_path,confirm=True)

        # Extract the zipped folder to a temporary directory

        temp_directory = path + "temp"
        # command_extract = f'"C:/Program Files/WinRAR/WinRAR.exe" x -ibck {remote_file_path} {temp_directory}'
        try:
            # Execute the unzip command on the remote server
            command = f'unzip -o {remote_file_path} -d {temp_directory}'
            stdin, stdout, stderr = ssh_conn['ssh_client'].exec_command(command)

            # Wait for the command to complete
            stdout.channel.recv_exit_status()

            command_last_directory = f'dir /ad /b /o-n "{temp_directory}"'
            stdin, stdout, stderr = ssh_conn['ssh_client'].exec_command(command_last_directory)

            # Move the files from the last directory to the root directory
            # command_move_files = f'for /R "{temp_directory}" %F in (*) do move /Y "%F" {path}'windows
            # command_move_files = f'find "{temp_directory}" -type f -exec mv -i {{}} "{path}" \\;'
            command_move_files = f'find "{temp_directory}" -type f -exec mv -f {{}} "{path}" \\;'
            stdin, stdout, stderr = ssh_conn['ssh_client'].exec_command(command_move_files)

            # Delete all files in temp directory
            #command_delete_temp_files = f'find "{temp_directory}" -mindepth 1 -delete'#f'find "{temp_directory}" -type f -exec rm -f {{}} +'
            #stdin, stdout, stderr = ssh_conn['ssh_client'].exec_command(command_delete_temp_files)

            # Delete zipped folder
            command_delete_zipped_folder = f'rm -f {remote_file_path}'
            stdin, stdout, stderr = ssh_conn['ssh_client'].exec_command(command_delete_zipped_folder)

        except Exception as e:
            print("Exception",e)

    except Exception as e:
        print(e)


def retrieve_data_owner_key(key, owner=0):
    service_name = "SSEDATAOWNER" + str(owner)
    if key == "KG":
        return keyring.get_password(service_name, "KG")
    elif key == "KSKE":
        return keyring.get_password(service_name, "KSKE")


def hash256(word):
    return hashlib.sha256(bytes(word, 'utf-8')).hexdigest()


def send_keys(entity, key, data_owner=0):
    key_kg = ""
    key_kske = ""
    keystore = redis_key_store_connection()
    if entity == "TA":
        print("reached here TA")
        encrypted_key = encrypt_rsa(key, retrieve_public_key("TA"))
        print("Ta",encrypted_key)
        keystore.hmset('dataowner' + str(data_owner), {'KG': encrypted_key})
        keystore.set('KG', encrypted_key)

    if entity == "DELAUTH":
        print("keys",key)
        print("DAL",retrieve_public_key("DELAUTH"))
        encrypted_key = encrypt_rsa(key, retrieve_public_key("DELAUTH"))
        print("Delauth",encrypted_key)
        keystore.hmset('dataowner' + str(data_owner), {'KSKE': encrypted_key})
        keystore.set('KSKE', encrypted_key)

    if entity == "POLICY":
        keystore.hmset('policy' + str(data_owner), {'CP': key})
        keystore.set('CP', key)

def retrieve_key(key, data_owner=0):
    keystore = redis_key_store_connection()
    result = keystore.hgetall('dataowner' + str(data_owner))
    #print("results",result)
    decrypted_key = ""
    if key == "KG":
        # decrypted_key = decrypt_rsa(keystore.get("KG"), retrieve_private_key("TA"))
        decrypted_key = decrypt_rsa(result['KG'], retrieve_private_key("TA"))
        print("Key",decrypted_key)
    elif key == "KSKE":
        # decrypted_key = decrypt_rsa(keystore.get("KSKE"), retrieve_private_key("DELAUTH"))
        #print("KSKE", result['KSKE'])
        decrypted_key = decrypt_rsa(result['KSKE'], retrieve_private_key("DELAUTH"))

    elif key == "TA":
        decrypted_key = decrypt_rsa_chunked(keystore.get("TA"), retrieve_private_key("TA"))

    elif key.find("policy") != -1:
        result = keystore.hgetall('policy' + key[6:])
        decrypted_key =result['CP']

    return decrypted_key


def redis_key_store_connection():
    redis_host = os.environ.get('REDIS_HOST', '88.193.177.146')
    redis_port = os.environ.get('REDIS_PORT', 6379)
    redis_password = os.environ.get('REDIS_PASSWORD', None)
    r = redis.StrictRedis(host=redis_host, port=redis_port, password=redis_password, decode_responses=True)
    return r


def open_socket_conn(server_ip, port, action):
    sockets = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (server_ip, port)  # replace with your server address

    if action == "send":
        sockets.connect(server_address)
        return sockets
    elif action == "rec":
        sockets.bind(server_address)
        sockets.listen(1)
        return sockets


def add_files(folder_dic):
    os.chdir(folder_dic)
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
            with open(file, 'r') as f:
                for word in f.read().split():
                    found_dicts = [d for d in word_list if d["word"] == word and d['filename'] == f.name]
                    if not found_dicts:
                        distinct_words = {"word": word, "filename": f.name, "file_id": count_no_of_file}
                        word_list.append(distinct_words)
                key = os.urandom(32)
                output_folder = 'encrypted_files'

                list_of_cipher_text.append(f.name)
                # list_of_cipher_text.append(encrypt_aes(f.name, retrieve_data_owner_key("KSKE"), True))
                # encrypt_aes(str(found_word['file_id']), retrieve_data_owner_key("KSKE"), True)
                # cipher_file_id = cipher_file_id + 1
                # list_of_cipher_file_id.append(str(cipher_file_id))
                cipher_file_name = encrypt_aes(f.name, retrieve_data_owner_key("KSKE"), True)

                os.makedirs(output_folder, exist_ok=True)
                encrypt_aes_file(f.name, retrieve_data_owner_key("KSKE"), output_folder, f.name)
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

        key_word_encrypted = iprf_aes(message, retrieve_data_owner_key("KG"))
        address_keyword = hash256(key_word_encrypted + str(no_of_file))

        found_dicts = [d for d in dict_words if d["word"] == word]
        for found_word in found_dicts:
            val_key_word = encrypt_aes(str(found_word['file_id']) + str(count), retrieve_data_owner_key("KSKE"))
            # print(val_key_word)
            list_of_address_keyword.append(address_keyword)
            list_of_val_key_word.append(val_key_word)

            cipher_file_id = cipher_file_id + 1
            # list_of_cipher_file_id.append(
            #   encrypt_aes(str(found_word['file_id']), retrieve_data_owner_key("KSKE"), True))
            list_of_cipher_file_id.append(str(found_word['file_id']) + '.enc')

    map['address'] = list_of_address_keyword
    map['val_key'] = list_of_val_key_word

    vals = {'map': map, 'no_of_files': list_of_no_of_files, 'no_of_search': list_of_no_of_search,
            'cipher': list_of_cipher_text, 'cipher_id': list_of_cipher_file_id, 'enc_dir': folder_dic,
            'h_keyword': list_of_hashed_keyword}
    current_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(current_dir)

    with open('temp_files.pkl', 'wb') as f:
        pickle.dump(vals, f)


def sending_files(data_owner=0, send_key=True):
    c = {}
    all_map = {}
    data_dict = {}

    with open('temp_files.pkl', 'rb') as f:
        loaded_variable = pickle.load(f)
        # path_to_enc_files = loaded_variable['enc_dir'] + '\\' + "encrypted_files"
        path_to_enc_files = os.getcwd() + '/' + "encrypted_files"
        dest_zipped_location = loaded_variable['enc_dir']
        zip_obj = zipfile.ZipFile(dest_zipped_location + '/zipped_folder.zip', 'w', zipfile.ZIP_DEFLATED)
        for root, dirs, files in os.walk(path_to_enc_files):
            for file in files:
                if not file.endswith('.zip'):
                    zip_obj.write(os.path.join(root, file))
        zip_obj.close()

        all_map['map'] = loaded_variable['map']
        all_map['cid'] = loaded_variable['cipher_id']

        start_time = time.time()
        csp_recieves_files(all_map, data_owner)
        exec_time = float(time.time() - start_time)
        print("Time Take to Send to CSP is " + str(exec_time))
        # uploading enc files
        print("des",dest_zipped_location)
        upload_cipher(dest_zipped_location)

    # sending no.files and no.searches to TA
    string_of_no_of_files = ','.join(loaded_variable['no_of_files'])
    string_of_no_of_search = ','.join(loaded_variable['no_of_search'])
    string_of_hashed_keyword = ','.join(loaded_variable['h_keyword'])

    encrypted_no_of_file = encrypt_rsa_chunked(string_of_no_of_files, retrieve_public_key("TA"))
    encrypted_no_of_search = encrypt_rsa_chunked(string_of_no_of_search, retrieve_public_key("TA"))
    encrypted_hashed_keyword = encrypt_rsa_chunked(string_of_hashed_keyword, retrieve_public_key("TA"))
    ta_receives_files(encrypted_no_of_file, encrypted_no_of_search, encrypted_hashed_keyword, data_owner)

    if send_key:
        # send KSKE to delauth
        send_keys("DELAUTH", retrieve_data_owner_key("KSKE", data_owner), data_owner)

        # send KG to Ta
        send_keys("TA", retrieve_data_owner_key("KG", data_owner), data_owner)


def ta_receives_files(no_of_files, no_of_searchs, encrypted_hashed_keyword, data_owner):
    dbresult = dbconnect("ta")
    decrypted_no_of_file_str = decrypt_rsa_chunked(no_of_files, retrieve_private_key("TA"))
    no_of_files_list = decrypted_no_of_file_str.split(",")
    decrypted_no_of_search_str = decrypt_rsa_chunked(no_of_searchs, retrieve_private_key("TA"))
    no_of_search_list = decrypted_no_of_search_str.split(",")

    decrypted_hashed_keyword = decrypt_rsa_chunked(encrypted_hashed_keyword, retrieve_private_key("TA"))
    hashed_keyword_list = decrypted_hashed_keyword.split(",")
    # send KG to TA
    # send_keys("TA", generate_kg())
    for no_file, no_search, hash_word in zip(no_of_files_list, no_of_search_list, hashed_keyword_list):
        # checking if hash exits (same)
        dbresult[0].execute("select * from no_filesearch where hword='" + hash_word + "'")
        results = dbresult[0].fetchall()
        if len(results) > 0:
            no_search = str(int(results[0][2]))
            no_files = str(int(results[0][1]))
            dbresult[0].execute(
                "update no_filesearch set no_of_search ='" + no_search + "', no_of_file='" + no_file + "'where hword='" + hash_word + "'")
            dbresult[1].commit()
        else:
            sql = "insert into no_filesearch(no_of_file,no_of_search,hword,data_owner) values(%s,%s,%s,%s)"
            val = [(no_file, no_search, hash_word, data_owner)]
            dbresult[0].executemany(sql, val)
            hey= dbresult[1].commit()




def csp_recieves_files(dict, data_owner):
    str_address = ','.join(dict['map']['address'])
    val_key = dict['map']['val_key']
    encrypted_address = encrypt_rsa_chunked(str_address, retrieve_public_key("CSP"))
    # encrypted_file_id = encrypt_rsa_chunked(','.join(dict['cid']), retrieve_public_key("CSP"))
    cfid = ','.join(dict['cid'])
    csp_file_save(encrypted_address, val_key, dict['cid'], data_owner)


def csp_file_save(encrypted_address, val_key, encrypted_file_id, data_owner):
    dbresult = dbconnect("csp")
    dec_address = decrypt_rsa_chunked(encrypted_address, retrieve_private_key("CSP"))

    list_dec_address = dec_address.split(',')
    # dec_file_id = decrypt_rsa_chunked(encrypted_file_id, retrieve_private_key("CSP"))
    # list_dec_file_id = dec_file_id.split(',')
    list_dec_file_id = encrypted_file_id

    list_enc_file_id = []
    for address, file_id, val_key in zip(list_dec_address, encrypted_file_id, val_key):
        sql = "insert into files(address,val,cfid,data_owner) values(%s,%s,%s,%s)"
        val = [(address, val_key, file_id, data_owner)]
        dbresult[0].executemany(sql, val)
        dbresult[1].commit()


def dbconnect(database):
    dbpams = []
    config ={
        'host':"88.193.177.146",
        'user':"deleteAuth",
        'password':"root",
        'database':database,
        'ssl_disabled':True,
        'port':'3306',

        'auth_plugin' : 'mysql_native_password'
    }
    mydb = mysql.connector.connect(**config)
    #mydb=mysql.connector.connect(host='88.193.177.146',port="3306",user='delauth',password='root',database=database,ssl_disabled=True)
    mycursor = mydb.cursor()
    dbpams.append(mycursor)
    dbpams.append(mydb)
    return dbpams


# print(retrieve_data_owner_key("KG"))
# generate_key()
# print(retrieve_data_owner_key("KG"))
# send_keys("TA")
# sending_files("Denis")

# add_files("C:\\files")

def search(keyword, data_owner=0):
    hashed_keyword = hash256(keyword)
    results = search_ta(hashed_keyword, data_owner)
    return results


def search_ta(hashed_keyword, data_owner=0):
    lup = []
    resultdb = dbconnect("ta")
    resultdb[0].execute("select * from no_filesearch where hword='" + hashed_keyword + "'")
    results = resultdb[0].fetchall()
    if len(results) > 0:
        no_search = results[0][2]
        no_files = int(results[0][1])
        key_word_encrypted = iprf_aes(hashed_keyword + no_search, retrieve_key("KG", data_owner))
        no_search = int(no_search) + 1
        new_key_word_encrypted = iprf_aes(hashed_keyword + str(no_search), retrieve_key("KG", data_owner))

        update_ta_search(resultdb, hashed_keyword)
        for i in range(1, no_files + 1):
            new_address = hash256(new_key_word_encrypted + str(i))
            lup.append(new_address)
        results = search_csp(key_word_encrypted, new_key_word_encrypted,
                             encrypt_rsa(str(no_files), retrieve_public_key("CSP")),
                             lup)
        return results
    else:
        print("No keyword found")
        print("\n")


def search_csp(keyword_enc, new_key_word_encrypted, no_file_enc, lup):
    rwj = None
    results = []
    decrypted_no_file = decrypt_rsa(no_file_enc, retrieve_private_key("CSP"))

    for i in range(1, int(decrypted_no_file) + 1):
        val_address = hash256(keyword_enc + str(i))

        if query_dictionary(val_address) is not None:
            rwj = query_dictionary(val_address)

        # csp_del_entries(val_address, lup)
    # delauth_rec_search_results(rwj, new_key_word_encrypted)
    result_no = 1
    last_no = 0;
    for cfid in rwj['cfid']:
        results.append({'results': cfid, 'id': result_no})
        print(result_no, ':', cfid)
        result_no = result_no + 1
        last_no = result_no
    if last_no > 2:
        print(last_no, ":", "All files")

    with open('temp_download_files.pkl', 'wb') as f:
        pickle.dump({'results': results, 'last_option': last_no}, f)

    csp_update_entries(lup, rwj['id'])
    return results


def query_dictionary(hashed_keyword):
    resultdb = dbconnect("csp")
    resultdb[0].execute("select val,cfid,id,address from files where address='" + hashed_keyword + "'")
    results = resultdb[0].fetchall()
    list_val = []
    list_cfid = []
    list_id = []
    if len(results):
        for row in results:
            list_val.append(row[0])
            list_cfid.append(row[1])
            list_id.append((row[2]))

        return {'val': list_val, 'cfid': list_cfid, 'id': list_id}


def update_ta_search(connection, hashed_keyword):
    connection[0].execute(
        "update no_filesearch set no_of_search = no_of_search+ 1 where hword='" + hashed_keyword + "'")
    connection[1].commit()


def csp_update_entries(lup, list_id):
    resultdb = dbconnect("csp")
    new_address = lup[-2]
    for address_id in list_id:
        resultdb[0].execute(
            "update files set address ='" + new_address + "' where id='" + str(address_id) + "'")
        resultdb[1].commit()


def delauth_rec_search_results(rwj, new_key_word_encrypted, data_owner):
    for cfid in rwj['cfid']:
        file_id = decrypt_aes(cfid, retrieve_key("KSKE", data_owner))


def csp_del_entries(old_add, lup):
    resultdb = dbconnect("csp")
    resultdb[0].execute("select id,address,val,cfid from files where address='" + old_add + "'")
    results = resultdb[0].fetchall()
    if len(results) > 0:
        print(results)


def download_files(file_id):
    with open('temp_download_files.pkl', 'rb') as f:
        loaded_variable = pickle.load(f)
        if not is_id_in_list(file_id, loaded_variable['results']) and int(file_id) > int(
                loaded_variable['last_option']):
            print("invalid option, please enter the available options")
            return False

        download(loaded_variable, file_id)
        print("files successfully downloaded")


def is_id_in_list(id_to_search, data_list):
    for item in data_list:
        if item['id'] == int(id_to_search):
            return True
    return False


def download(files, file_id):
    ssh_conn = ssh_connection()

    download_dir = os.path.expanduser('~\\Downloads')
    if int(file_id) == int(files['last_option']):
        for file in files['results']:
            remote_file_path = "/home/delauth/files" + file['results']
            local_file_path = os.path.join(download_dir, os.path.basename(remote_file_path))
            ssh_conn['sftp_client'].get(remote_file_path, local_file_path)
    else:
        for file in files['results']:
            if int(file['id']) == int(file_id):
                remote_file_path = "/home/delauth/files" + file['results']
                local_file_path = os.path.join(download_dir, os.path.basename(remote_file_path))
                ssh_conn['sftp_client'].get(remote_file_path, local_file_path)

    # Close the SFTP session and the SSH client
    ssh_conn['sftp_client'].close()
    ssh_conn['ssh_client'].close()


def decrypt_download_files(file_id):
    download_dir = os.path.expanduser('~\\Downloads')
    decrypted_filename = []
    result_no = 1
    last_no = 0
    filename = []
    with open('temp_download_files.pkl', 'rb') as f:
        loaded_variable = pickle.load(f)
        # print(loaded_variable)
        if not is_id_in_list(file_id, loaded_variable['results']) and int(file_id) > int(
                loaded_variable['last_option']):
            print("invalid option, please enter the available options")
            return False

        if int(file_id) == int(loaded_variable['last_option']):
            for file in loaded_variable['results']:
                # file_name = decrypt_aes(file['results'], retrieve_data_owner_key("KSKE"), True)
                decrypt_aes_file(file['results'], retrieve_data_owner_key("KSKE"), download_dir, file['results'])
                decrypted_filename.append(os.path.splitext(file['results'])[0])
        else:
            for file in loaded_variable['results']:
                if int(file['id']) == int(file_id):
                    decrypt_aes_file(file['results'], retrieve_data_owner_key("KSKE"), download_dir, file['results'])
                    decrypted_filename.append(os.path.splitext(file['results'])[0])

        for dec_files in decrypted_filename:
            filename.append({'results': dec_files, 'id': result_no})
            result_no = result_no + 1
            last_no = result_no
        if int(file_id) == int(loaded_variable['last_option']):
            print(last_no, ":", "All files")

    with open('encrypted_files.pkl', 'wb') as f:
        pickle.dump({'filename': filename, 'last_option': last_no}, f)
    print("Files decrypted successfully")


def view_downloaded_files(file_id):
    location = os.path.expanduser('~\\Downloads')
    os.chdir('..')
    os.chdir("SYSSE")
    with open('encrypted_files.pkl', 'rb') as f:
        loaded_variable = pickle.load(f)
        if not is_id_in_list(file_id, loaded_variable['filename']) and int(file_id) > int(
                loaded_variable['last_option']):
            print("invalid option, please enter the available options")
            return False
        if int(file_id) == int(loaded_variable['last_option']):
            for file in loaded_variable['filename']:
                op_file = open(location + '/' + file['results'], 'r')
                print(
                    "**********************************************    " + file[
                        'results'] + "    ***********************************")
                contents = op_file.read()
                print(contents)
                op_file.close()
                print("\n")
        else:
            for file in loaded_variable['filename']:
                if int(file['id']) == int(file_id):
                    op_file = open(location + '/' + file['results'], 'r')
                    print(
                        "**********************************************    " + file[
                            'results'] + "    ***********************************")
                    contents = op_file.read()
                    print(contents)
                    op_file.close()
                    print("\n")


def fetch_data_owner():
    resultdb = connection("sse")
    resultdb[0].execute("select id,username from authapp_user where role='data_owner'")
    results = resultdb[0].fetchall()
    data_owner = []
    data_owner.append({'id': 0, 'value': '--Please select--'})
    for result in results:
        data_owner.append({'id': result[0], 'value': result[1]})

    return data_owner


def is_key_word_exists(connect, hash_word):
    connect[0].execute("select * from no_filesearch where hword='" + hash_word + "'")
    results = connect[0].fetchall()
    if len(results) > 0:
        no_search = results[0][2]
        return no_search
    else:
        return False

def abe_gen():
    (master_public_key,master_key,group)= key_gen_abe()
    mpk_bytes = objectToBytes(master_public_key, group)
    resultdb = connection("pubkeyauth")
    sql = "insert into keygen_publickey(key_id,key_data) values (%s,%s)"
    val = [("ta-abe",mpk_bytes)]
    resultdb[0].executemany(sql, val)
    resultdb[1].commit()

    keystore = redis_key_store_connection()
    keystore.set("TA",encrypt_rsa_chunked(objectToBytes(master_key, group).decode(), retrieve_public_key("TA")))



def encrypt_policy(data_owner):
    resultdb = connection("sse")
    sql = "select * from authapp_policy   limit 1"
    resultdb[0].execute(sql)
    results = resultdb[0].fetchall()
    access_policy = results[0][1]

    master_public_key = retrieve_public_key("ta-abe").encode('utf-8')
    kske = retrieve_key("KSKE",data_owner)
    group = PairingGroup('SS512')
    cpabe = CPabe_BSW07(group)
    hyb_abe = HybridABEnc(cpabe,group)
    mpk = bytesToObject(master_public_key,group)
    ciphertext = hyb_abe.encrypt(mpk, kske, access_policy)
    ciphertext_bytes = objectToBytes(ciphertext,group)
    send_keys("POLICY",ciphertext_bytes,data_owner)


# download_files()
# print(retrieve_data_owner_key("KG"))
# print(IPRF_AES("Denis", retrieve_data_owner_key("KG")))
# decrypt_download_files()
# print(retrieve_data_owner_key("KSKE","14"))
