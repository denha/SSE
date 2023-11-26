from keygen.models import PublicKey
import paramiko
import jks

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

        # Close the SSH connection
        ssh.close()
        return private_key
    except Exception as e:
        print("error" + str(e))



def retrieve_public_key(key_id, user_id=""):
    try:
        is_key_exists = PublicKey.objects.using('public_keyauth').filter(key_id=key_id.lower(),
                                                                         user_id=user_id).exists()
        records = PublicKey.objects.using('public_keyauth').get(key_id=key_id.lower(), user_id=user_id)

        if is_key_exists:
            return records.key_data.decode()
        else:
            print("Key Id does not exist")
    except Exception as e:
        print("error" + str(e))


