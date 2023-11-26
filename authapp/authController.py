import bcrypt

from authapp.genkeypair import *
from authapp.models import *
from keygen.keygen import generate_key, retrieve_data_owner_key, send_keys,retrieve_key,redis_key_store_connection
from keygen.keys import  retrieve_private_key,retrieve_public_key
from authapp.crypto import decrypt_rsa_chunked,secret_key_gen,encrypt_rsa_chunked
from charm.toolbox.pairinggroup import PairingGroup
from charm.core.engine.util import objectToBytes, bytesToObject


def _save_user(username, email, password, role):
    try:
        is_email_exists = User.objects.filter(email=email).exists()
        is_username_exists = User.objects.filter(username=email).exists()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        if not is_email_exists or not is_username_exists:
            user = User(email=email, username=username, password=hashed_password, role=role)
            user.save()

            # saving public key to db
            save_user_public_key(str(hashed_password[:6]).replace('$','X'),"user"+str(user.id))

            # generate keys role is data owner
            if role == "data_owner":
                print("here")
                generate_key(user.id)
                send_keys("TA", retrieve_data_owner_key("KG", user.id), user.id)
                send_keys("DELAUTH", retrieve_data_owner_key("KSKE", user.id), user.id)



            return user.id

    except Exception as e:
        print("yes",e)
        return e

def send_user_attributes_to_ta(attrs,user_id):
    dec_attributes = decrypt_rsa_chunked(attrs,retrieve_private_key("TA"))
    print(dec_attributes)
    mpk = retrieve_public_key("ta-abe").encode('utf-8')
    msk = retrieve_key("TA").encode('utf-8')
    sk = secret_key_gen(mpk,msk,dec_attributes)
    keystore = redis_key_store_connection()
    group = PairingGroup('SS512')
    sk_bytes = objectToBytes(sk, group)
    keystore.hmset('user' + str(user_id), {'KEY': encrypt_rsa_chunked(sk_bytes.decode(),retrieve_public_key("user"+str(user_id)))})

def _policy(name,data_owner_id,default):
    try:
        policy = Policy(name=name,data_owner_id=data_owner_id,default=default)
        policy.save()
        return True
    except Exception as e:
        print("yes",e)
        return e

def _view_policy(data_owner_id):
    try:

        policy = Policy.objects.values('id','name','default').filter(data_owner_id=data_owner_id)

        return policy
    except Exception as e:
        print("yes",e)
        return e