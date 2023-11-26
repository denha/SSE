"""from charm.schemes.abenc.abenc_lsw08 import KPabe
from charm.toolbox.pairinggroup import PairingGroup,GT
group = PairingGroup('MNT224')
kpabe = KPabe(group)
(master_public_key, master_key) = kpabe.setup()
policy = '(ONE or THREE) and (THREE or TWO)'
attributes = [ 'ONE', 'TWO', 'THREE', 'FOUR' ]
secret_key = kpabe.keygen(master_public_key, master_key, policy)
msg=group.random(GT)
cipher_text = kpabe.encrypt(master_public_key, msg, attributes)
decrypted_msg = kpabe.decrypt(cipher_text, secret_key)
print(decrypted_msg == msg)"""
from charm.core.math.pairing import GT
from charm.schemes.abenc.abenc_bsw07 import ABEnc, CPabe_BSW07
from charm.schemes.abenc.abenc_waters09 import CPabe09
from charm.toolbox.pairinggroup import PairingGroup

"""from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
group = PairingGroup('SS512')
cpabe = CPabe_BSW07(group)
msg = group.random(GT)
attributes = ['ONE', 'TWO', 'THREE']
access_policy = '((four or three) and (three or one))'
(master_public_key, master_key) = cpabe.setup()
secret_key = cpabe.keygen(master_public_key, master_key, attributes)
cipher_text = cpabe.encrypt(master_public_key, msg, access_policy)
decrypted_msg = cpabe.decrypt(master_public_key, secret_key, cipher_text)
msg == decrypted_msg"""
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
group = PairingGroup('SS512')
cpabe = CPabe_BSW07(group)
msg = group.random(GT)
attributes = ['ONE', 'TWO', 'THREE']
access_policy = '((four or three) and (three or one))'
(master_public_key, master_key) = cpabe.setup()
secret_key = cpabe.keygen(master_public_key, master_key, attributes)
cipher_text = cpabe.encrypt(master_public_key, msg, access_policy)
decrypted_msg = cpabe.decrypt(master_public_key, secret_key, cipher_text)
msg == decrypted_msg




