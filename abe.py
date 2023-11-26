from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.adapters.abenc_adapt_hybrid import HybridABEnc
import ast
import json
import pickle
from charm.core.engine.util import objectToBytes, bytesToObject

def ABE():
    group = PairingGroup('SS512')
    cpabe = CPabe_BSW07(group)
    hyb_abe = HybridABEnc(cpabe,group)
    (master_public_key, master_key) = hyb_abe.setup()
    access_policy = '(ONE or TWO or THREE)'
    sk = hyb_abe.keygen(master_public_key, master_key, ['THREE'])
    ciphertext = hyb_abe.encrypt(master_public_key, "DENIS", access_policy)
    decrypted_msg = hyb_abe.decrypt(master_public_key, sk, ciphertext)
    #print(decrypted_msg)
    #print(master_public_key)
    #print(master_key)

    #print(msk)
    #print(mpk)
    print("\n")
    #print(master_key)
    #print(master_public_key)
    #print(hyb_abe.keygen(mpk, msk, ['THREE']))
    #print(str([master_key]))
    #print(type(ast.literal_eval(str([master_key]))[0]))
    #print(ast.literal_eval(str([master_public_key]))[0])
    #sk1 = hyb_abe.keygen(ast.literal_eval(str([master_public_key]))[0], ast.literal_eval(str([master_key]))[0], ['THREE'])
    #sk1 = hyb_abe.keygen(master_public_key, master_key,['THREE'])
    #print(master_key)
    #print(sk1)
    #print(json.dumps(master_public_key))
    #him = pickle.dumps(master_public_key)
    mpk_bytes = objectToBytes(master_public_key,group)
    msk_bytes = objectToBytes(master_key, group)
    mpk = bytesToObject(mpk_bytes,group)
    msk = bytesToObject(msk_bytes, group)
    sk1 = hyb_abe.keygen(mpk, msk,['THREE'])
    print(mpk )
    print(mpk_bytes)
ABE()
