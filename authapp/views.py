import json
import os
import pickle
import subprocess
from datetime import time
from django.views.decorators.http import require_http_methods
#import dropbox
#import xmltodict

from django.http import HttpResponse, HttpResponseRedirect
from jks import print_pem
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response

from django.shortcuts import redirect, render
#from dropbox import DropboxOAuth2Flow, DropboxOAuth2FlowNoRedirect, Dropbox
from authapp.authController import _save_user,send_user_attributes_to_ta,_policy,_view_policy
from authapp.crypto import encrypt_aes, encrypt_aes_file, encrypt_aes_file_sync, iprf_aes, encrypt_rsa_chunked
from authapp.genkeypair import user_log_in
from keygen.keygen import retrieve_data_owner_key, hash256, sending_files
from keygen.keys import retrieve_public_key, retrieve_private_key
#from dropbox.exceptions import AuthError
"""import requests
import xml.etree.ElementTree as ET
from urllib.parse import urljoin"""


# from keygen.views import get_private_key


# Create your views here.
@api_view(['POST'])
def user_register(request):

    try:
        username = request.data.get('username')
        email = request.data.get('email')
        password = request.data.get('password')
        role = request.data.get('role')
        attr = request.data.get('attr')

        if username != "" or email != "" or password != "" or role != "" :
            user_id = _save_user(username, email, password, role)
            if attr != "":
                send_user_attributes_to_ta(encrypt_rsa_chunked(attr,retrieve_public_key("TA")),user_id)

            return Response({'message': 'user created', 'status': True}, status=status.HTTP_201_CREATED)
        else:
            return Response({'message': 'Fill in all the fields', 'status': False}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'message': e, 'status': False}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(['POST'])
def user_login(request):
    try:
        email = request.data.get('email')
        password = request.data.get('password')

        if email != "" or password != "":
            user = user_log_in(email, password)
            if user:
                return Response({'message': 'success', 'status': True, 'data': user}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'invalid email or password', 'status': False}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Fill in all the fields', 'status': False}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'message': e, 'status': False}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
def data_policy(request):
    try:
        name = request.data.get('name')
        data_owner_id = request.data.get('data_owner_id')
        default= request.data.get('default')
        if name != "":
            policy = _policy(name,data_owner_id,default)
            if policy:
                print('here')
                return Response({'message': 'success', 'status': True, 'data': ''}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'invalid email or password', 'status': False}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Fill in all the fields', 'status': False}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'message': e, 'status': False}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
@api_view(['GET'])
def view_policy(request,owner):
    try:

        if owner != "":
            policy = _view_policy(owner)
            if policy:
                print('here')
                return Response({'message': 'success', 'status': True, 'data': policy}, status=status.HTTP_200_OK)
            else:
                return Response({'message': 'invalid email or password', 'status': False}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Fill in all the fields', 'status': False}, status=status.HTTP_200_OK)

    except Exception as e:
        return Response({'message': e, 'status': False}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

def callback(request):
    authorization_code = request.GET.get('code')
    os.environ["authToken"] = authorization_code
    auth_token = os.environ["authToken"]
    #print(auth_token)
    script_path = "/usr/local/src/charm-dev/fileSync.py"
    subprocess.Popen(['python3', script_path])
    #process = subprocess.Popen(['python3', script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    #print(authorization_code)
    print("here")
    return HttpResponse("<h1>Sync Successful!</h1><p> <a href='http://localhost:3000/home'>Back </a></p>")



@api_view(['GET'])
def auth_index(request,dataowner):
    print("dataowner",dataowner)
    os.environ["data-owner"] = dataowner
    authorization_endpoint = 'http://88.193.178.23:8080/index.php/apps/oauth2/authorize'
    client_id = 'Sat1bLhgLJ5tCrzTEsbFWzGCr9RFbeNNoSeMB94MAqLUYLig85oDKWBbqA7DGtcZ'
    redirect_uri = 'http://88.193.178.239:8000/callback'
    scope = 'read write'  # Adjust the scope as needed

    authorization_url = f'{authorization_endpoint}?response_type=code&client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}'

    return Response({'message': 'success', 'status': True, 'data': authorization_url}, status=status.HTTP_200_OK)



def webhook(request):
    if request.method == 'POST':
        # Process the file event notification
        event_data = json.loads(request.body)
        file_path = event_data.get('path')
        event_type = event_data.get('type')

        # Perform actions based on the event data
        # Example: Print the file path and event type
        print(f'New file added: {file_path} (Event Type: {event_type})')
    print("from brwoser")
    return HttpResponse(status=200)


def AutoScript(request):
    print(os.getcwd() + "/keygen/keygen.py")
    script_path = "C:\Symetric Enc\SYSSE/fileSync.py"
    subprocess.Popen(['python', script_path])
    print('Script started')
    return HttpResponse(status=200)
