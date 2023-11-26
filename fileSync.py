import os
import pickle
import time
from urllib.parse import urljoin, unquote

import django
import keyring
import requests
import xml.etree.ElementTree as ET

from authapp.crypto import encrypt_aes, iprf_aes, encrypt_aes_file_sync
from keygen.keygen import sending_files, hash256, retrieve_key, is_key_word_exists, dbconnect,encrypt_policy

# Set the Django settings module
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'SYSSE.settings')

# Initialize Django
django.setup()


def get_keys(keys, dataowner):
    try:
        service_name = "SSEDATAOWNER" + str(dataowner)
        key = ""
        if keys == "KG":
            key = keyring.get_password(service_name, "KG")
        elif keys == "KSKE":
            key = keyring.get_password(service_name, "KSKE")
        return key
    except Exception as e:
        print(e)

print("house")

encrypt_policy(os.environ["data-owner"])
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
authorization_code = os.environ["authToken"]
new_files_detected = False
file_exists = False

# Step 4: Exchange the authorization code for an access token
token_endpoint = 'http://88.193.178.23:8080/index.php/apps/oauth2/api/v1/token'
client_id = 'Sat1bLhgLJ5tCrzTEsbFWzGCr9RFbeNNoSeMB94MAqLUYLig85oDKWBbqA7DGtcZ'
client_secret = '0VRDtEzUsvroiGYxwkq4ODSUNzJYByKe6BsCSPGFPaZIVg011WLyGZbYe1cblYgo'
redirect_uri = 'http://88.193.178.239:8000/callback'
access_token = ""
token_params = {
    'grant_type': 'authorization_code',
    'client_id': client_id,
    'client_secret': client_secret,
    'redirect_uri': redirect_uri,
    'code': authorization_code,
}
resultdb = dbconnect("ta")
response = requests.post(token_endpoint, data=token_params)
# print("enc", retrieve_data_owner_key("KSKE", "14"))
if response.status_code == 200:
    # Step 5: Receive the access token
    access_token = response.json().get('access_token')
    # print(f'Access token: {access_token}')
    # print('Authentication Successful!')

    api_endpoint = 'http://88.193.178.23:8080/remote.php/dav/files/denha/'

    # Set up the headers with the authorization token
    headers = {
        'Authorization': 'Bearer ' + access_token,
    }

    # Make the API request to retrieve synced files
    response = requests.request('PROPFIND', api_endpoint, headers=headers)

    previous_file_urls = set()

    while True:
        # Make the API request to retrieve synced files
        response = requests.request('PROPFIND', api_endpoint, headers=headers)

        # Check the response status code
        if response.status_code == 207:
            response_data = response.text

            # Parse the XML response
            root = ET.fromstring(response_data)

            # Namespace mapping
            namespaces = {
                'd': 'DAV:',
            }

            # Extract file URLs from the response
            file_urls = []
            for href_elem in root.findall('.//d:href', namespaces):
                file_url = href_elem.text
                # Exclude directories from the file URLs
                if not file_url.endswith('/'):
                    file_urls.append(file_url)

            # Detect newly added files
            new_file_urls = set(file_urls) - previous_file_urls

            if new_file_urls:
                print("All files", new_file_urls)
                # Set the flag to True if new files are detected
                new_files_detected = True
            # Iterate over the new file URLs and retrieve their content
            for file_url in new_file_urls:
                file_name = unquote(os.path.basename(file_url))
                file_exists = True
                # print("files", file_name)
                # Add the scheme to the file URL
                file_url = urljoin(api_endpoint, file_url)

                # Make a GET request to retrieve the file content
                file_response = requests.get(file_url, headers=headers)

                # Check the response status code
                if file_response.status_code == 200:
                    # Request successful, retrieve the file content
                    file_content = file_response.text
                    # print(file_content.split())

                    # Check whether file is in text format or not
                    if file_name.endswith(".txt"):
                        if new_files_detected and file_exists:
                            for word in file_content.split():
                                found_dicts = [d for d in word_list if
                                               d["word"] == word and d['filename'] == file_name]
                                if not found_dicts:
                                    distinct_words = {"word": word, "filename": file_name,
                                                      "file_id": count_no_of_file}
                                    word_list.append(distinct_words)
                            key = os.urandom(32)
                            output_folder = 'encrypted_files'

                            list_of_cipher_text.append(file_name)
                            cipher_file_name = encrypt_aes(file_name, get_keys("KSKE", os.environ["data-owner"]), True)

                            os.makedirs(output_folder, exist_ok=True)
                            encrypt_aes_file_sync(file_name, get_keys("KSKE", os.environ["data-owner"]), output_folder,
                                                  "",
                                                  file_content)
                            count_no_of_file = count_no_of_file + 1
                else:
                    # Request failed for the specific file
                    #print(
                        #f'Failed to retrieve file content for URL: {file_url}. Status Code: {file_response.status_code}')
                    print("hter is an error")
        if new_files_detected:
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

                resultdb = dbconnect("ta")
                hashed_no_of_search = is_key_word_exists(resultdb, key_word_hashed)
                if int(hashed_no_of_search) > 0:
                    message = key_word_hashed + str(hashed_no_of_search)
                else:
                    message = key_word_hashed + str(no_of_search)

                list_of_no_of_files.append(str(no_of_file))
                list_of_no_of_search.append(str(no_of_search))

                key_word_encrypted = iprf_aes(message, get_keys("KG", os.environ["data-owner"]))
                address_keyword = hash256(key_word_encrypted + str(no_of_file))

                found_dicts = [d for d in dict_words if d["word"] == word]
                for found_word in found_dicts:
                    val_key_word = encrypt_aes(str(found_word['file_id']) + str(count),
                                               get_keys("KSKE", os.environ["data-owner"]))
                    # print(val_key_word)
                    list_of_address_keyword.append(address_keyword)
                    list_of_val_key_word.append(val_key_word)

                    cipher_file_id = cipher_file_id + 1
                    # list_of_cipher_file_id.append(
                    #   encrypt_aes(str(found_word['file_id']), retrieve_data_owner_key("KSKE"), True))
                    list_of_cipher_file_id.append(str(found_word['file_id']) + '.enc')

            map['address'] = list_of_address_keyword
            map['val_key'] = list_of_val_key_word

            vals = {'map': map, 'no_of_files': list_of_no_of_files,
                    'no_of_search': list_of_no_of_search,
                    'cipher': list_of_cipher_text, 'cipher_id': list_of_cipher_file_id,
                    'enc_dir': 'encrypted_files',
                    'h_keyword': list_of_hashed_keyword}
            current_dir = os.path.dirname(os.path.abspath(__file__))

            os.remove('temp_files.pkl')
            with open('temp_files.pkl', 'wb') as f:
                pickle.dump(vals, f)
            sending_files(os.environ["data-owner"], False)
            new_files_detected = False
            file_exists = False
            vals = {}, list_of_val_key_word.clear(), list_of_no_of_search.clear(), list_of_no_of_files.clear(),
            list_of_cipher_file_id.clear(), list_of_address_keyword.clear(), list_of_hashed_keyword.clear(),
            list_of_cipher_text.clear()
            print("Done")
            # Update the previously fetched file URLs
            count_no_of_file = 1
            word_list.clear()
            previous_file_urls = set(file_urls)

        # Add a delay or implement a scheduler for periodic checks
        # time.sleep(60)  # Delay for 60 seconds before the next check

else:
    print('Failed to obtain access token.')
    print('Authentication Failed')
