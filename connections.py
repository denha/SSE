import os

import mysql.connector
import paramiko
import redis


def dbconnect(database):
    dbpams = []
    mydb = mysql.connector.connect(
        host="88.193.184.110",
        user="root",
        password="",
        database=database
    )
    mycursor = mydb.cursor()
    dbpams.append(mycursor)
    dbpams.append(mydb)
    return dbpams


def redis_key_store_connection():
    redis_host = os.environ.get('REDIS_HOST', '88.193.184.110')
    redis_port = os.environ.get('REDIS_PORT', 6379)
    redis_password = os.environ.get('REDIS_PASSWORD', None)
    r = redis.StrictRedis(host=redis_host, port=redis_port, password=redis_password, decode_responses=True)
    return r


def ssh_connection():
    # Set the hostname, username, and password for the virtual machine
    hostname = '88.193.184.110'
    username = 'sse'
    password = '#Include<stdio>12345'

    # Create an SSH client and connect to the virtual machine
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(hostname=hostname, username=username, password=password)

    sftp_client = ssh_client.open_sftp()
    return {'sftp_client': sftp_client, 'ssh_client': ssh_client}
