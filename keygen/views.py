# Create your views here.
from jks import print_pem
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from keygen.keys import *
from keygen.service import gen_pub_pri_key, show_pub_key, gen_kg_kske, retrieve_data_owner_key, publish_public_key, \
    encrypt_files, upload_files, search_files, download_file, decrypt_file, data_owner, retrieve_data_owner_key_dec, \
    select_files


@api_view(['POST'])
def gen_public_private_key(request):
    try:
        data = {'validity': request.data.get('validity'), 'cname': request.data.get('cname'),
                'ounit': request.data.get('ounit'),
                'organ': request.data.get('organ'), 'location': request.data.get('location'),
                'state': request.data.get('state'),
                'country': request.data.get('country'),
                'keystore_name': request.data.get('keystore_name')}
        message = ""
        if data['validity'] == "":
            message = "validity cannot be empty"

        elif data['cname'] == "":
            message = "cname cannot be emtpy"
        elif data['ounit'] == "":
            message = "ounit cannot be empty"
        elif data['state'] == "":
            message = "state cannot be empty"
        elif data['country'] == "":
            message = "country cannot be empty"
        elif data['location'] == "":
            message = "location cannot be empty"
        elif data['organ'] == "":
            message = "organ cannot be empty"
        elif data['keystore_name'] == "":
            message = "Keystore name is missing"

        if message != "":
            return Response({'message': message, 'status': False}, status=status.HTTP_200_OK)
        results = gen_pub_pri_key(data)

        return Response({'message': results['msg'], 'status': True, 'data': results['data']}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'message': e}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def view_public_key(request, alias):
    try:
        message = ""
        if alias == "":
            message = "Alias must have a value"
        if message != "":
            return Response({'message': message, 'status': False}, status=status.HTTP_200_OK)
        results = show_pub_key(alias)
        return Response({'message': results['msg'], 'status': True, 'data': results['data']}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'message': e}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def generate_data_owner_keys(request, key, owner):
    try:
        message = ""
        if key == "":
            message = "keys must not be empty"
        if message != "":
            return Response({'message': message, 'status': False}, status=status.HTTP_200_OK)
        results = gen_kg_kske(key, owner)
        return Response({'message': results['msg'], 'status': True, 'data': results['data']}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'message': e}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def get_secret_key(request, key, owner):
    try:
        message = ""
        if key == "":
            message = "keys must not be empty"
        if message != "":
            return Response({'message': message, 'status': False}, status=status.HTTP_200_OK)
        results = retrieve_data_owner_key(key, owner)
        return Response({'message': results['msg'], 'status': True, 'data': results['data']}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'message': e}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def publish_keypair(request, key):
    try:
        results = publish_public_key(key)
        return Response({'message': 'success', 'status': True}, status=status.HTTP_200_OK)
    except Exception as e:
        print(e)


@api_view(['POST'])
def encrypt(request, owner):
    try:
        message = ""
        if request.data.get('path') == "":
            message = "Path must not be empty"
        if message != "":
            return Response({'message': message, 'status': False}, status=status.HTTP_200_OK)
        results = encrypt_files(request.data.get('path'), owner, request.data.get('files'))
        return Response({'message': '', 'status': True}, status=status.HTTP_200_OK)
    except Exception as e:
        print(e)


@api_view(['POST'])
def upload(request, data_owner):
    try:
        results = upload_files(data_owner, request.data.get('files'))
        return Response({'message': '', 'status': True}, status=status.HTTP_200_OK)
    except Exception as e:
        print(e)


@api_view(['POST'])
def searches(request, word, owner):
    try:
        result = search_files(word, owner,request.data.get('key'),request.data.get('userId'))
        return Response({'message': 'success', 'status': True, 'data': result['data']}, status=status.HTTP_200_OK)
    except Exception as e:
        print(e)


@api_view(['GET'])
def download(request, file):
    try:
        result = download_file(file)
        return Response({'message': 'success', 'status': True, 'data': result['data']}, status=status.HTTP_200_OK)
    except Exception as e:
        print(e)


@api_view(['GET'])
def decrypt_download(request, file, owner,user_id):
    try:
        result = decrypt_file(file, owner,user_id)
        return Response({'message': 'success', 'status': True, 'data': result['data']}, status=status.HTTP_200_OK)
    except Exception as e:
        print(e)


@api_view(['GET'])
def view_file(request, file, owner,user_id):
    try:
        result = decrypt_file(file, owner,user_id)
        return Response({'message': 'success', 'status': True, 'data': result['data']}, status=status.HTTP_200_OK)
    except Exception as e:
        print(e)


@api_view(['GET'])
def data_owners(request):
    try:
        result = data_owner()
        return Response({'message': 'success', 'status': True, 'data': result['data']}, status=status.HTTP_200_OK)
    except Exception as e:
        print(e)


@api_view(['POST'])
def check_kske(request, key, owner):
    try:
        logged = False
        message = ""
        if key == "":
            message = "keys must not be empty"
        if message != "":
            return Response({'message': message, 'status': False}, status=status.HTTP_200_OK)
        check_key = request.data.get('key')
        results = retrieve_data_owner_key_dec(key, owner)
        print(results['data'])
        if check_key == results['data']:
            logged = True
        return Response({'message': results['msg'], 'status': True, 'data': logged}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'message': e}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def fetch_keys(request, key, owner):
    try:
        logged = False
        message = ""
        if key == "":
            message = "keys must not be empty"
        if message != "":
            return Response({'message': message, 'status': False}, status=status.HTTP_200_OK)

        results = retrieve_data_owner_key_dec(key, owner)
        return Response({'message': results['msg'], 'status': True, 'data': results['data']}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'message': e}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['GET'])
def file_select(request, path):
    try:
        message = ""
        if path == "":
            message = "Path cannot be empty"
        if message != "":
            return Response({'message': message, 'status': False}, status=status.HTTP_200_OK)

        results = select_files(path)
        return Response({'message': results['msg'], 'status': True, 'data': results['data']}, status=status.HTTP_200_OK)
    except Exception as e:
        return Response({'message': e}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
