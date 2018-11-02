# notes on secretsharing module below:
# - sudo -H pip install secret-sharing is needed first
# - secretsharing uses /dev/random by default, which is slow as it
#   gathers entropy from OS events - that's not only slow, but can
#   also frequently block, to get around this edit the source and
#   change it to use /dev/urandom which won't block
#   source to edit for me was:
#   /usr/local/lib/python2.7/dist-packages/secretsharing/entropy.py
import secretsharing as sss

import base64
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES

from passlib.hash import pbkdf2_sha256,argon2,sha512_crypt,sha1_crypt
from random import randrange
import jsonpickle
from hashlib import sha256
import base64


# for encryptingfrom crypto.Cipher import AES you need: sudo -H pip install pycrypto
def pxor(pwd,share):

    '''
      XOR a hashed password into a Shamir-share
      1st few chars of share are index, then "-" then hexdigits
      we'll return the same index, then "-" then xor(hexdigits,sha256(pwd))
      we truncate the sha256(pwd) to if the hexdigits are shorter
      we left pad the sha256(pwd) with zeros if the hexdigits are longer
      we left pad the output with zeros to the full length we xor'd
    '''
    words=share.split("-")
    hexshare=words[1]
    slen=len(hexshare)
    hashpwd=sha256(pwd).hexdigest()
    hlen=len(hashpwd)
    outlen=0
    if slen<hlen:
        outlen=slen
        hashpwd=hashpwd[0:outlen]
    elif slen>hlen:
        outlen=slen
        hashpwd=hashpwd.zfill(outlen)
    else:
        outlen=hlen
    xorvalue=int(hexshare, 16) ^ int(hashpwd, 16) # convert to integers and xor
    paddedresult='{:x}'.format(xorvalue)          # convert back to hex
    paddedresult=paddedresult.zfill(outlen)       # pad left
    result=words[0]+"-"+paddedresult              # put index back
    return result


def pwds_shares_to_secret(kpwds,kinds,diffs):
    '''
        take k passwords, indices of those, and the "public" shares and
        recover shamir secret
    '''
    shares=[]
    for i in range(0,len(kpwds)):
        shares.append(pxor(kpwds[i],diffs[kinds[i]]))

    secret=sss.SecretSharer.recover_secret(shares)
    return secret

# modified from https://www.quickprogrammingtips.com/python/aes-256-encryption-and-decryption-in-python.html
BLOCK_SIZE = 16
pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

def encrypt(raw, key):
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))

unpad = lambda s: s[:-ord(s[len(s) - 1:])]
#password = input("Enter encryption password: ")


def get_private_key(password):
    salt = b"this is a salt"
    kdf = PBKDF2(password, salt, 64, 1000)
    key = kdf[:32]
    return key

def decrypt(enc, password):
    private_key = password#get_private_key(password)
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))


pwds = ["ClemNate", "rearSikh", "lopsDior"]#, "antakya", "Booter", "weeds425"]#, "watt2004"]#, "tqep8383", "tikionna", "sissy111", "sisozine", "sam4min", "rickejeh", "rufus139"]
shares = ["8-7b2f6f68df28cf49380ade1479c1ec4e3021b79f079f4657e0df517802070029","94-1973177500dd2976f5021ab8fae7b6915f29670fedebd234ecdcd026ab952d57","98-2779c6714ed81abfd16e0d55e3ef604b34f4307c9dd53139d6544828d3b09949"]#,"16-f1d390ed44b68ad6d11c09b084e531d7","24-3ecb653a71c2282654282be8b99440c2","a-be24d7e38817a5c32da1698ec2e2fb67"]#,"28-0b154be9ba9f71dc66396a12c8c7fb46"]#,"15-9bf6e58e58b60349703509622af807dc","26-d0a48a10527e8825e089892deea0d563","17-e59a9a9c5acae58a17bc7f2dd7a776da","20-195bd12323085f12d93066c4c9c776ed","1d-0a0205933641833b8ebb187fb22bf9a1","b-9196fe70d7499894a309ef3a43163924","1b-07653c3f27e5c5ca6e97032c7ed95c21",]
kinds = [0, 1,2,]#3,4,5]
secret = pwds_shares_to_secret(pwds,kinds, shares)

enc =""
result = decrypt(jsonpickle.encode(enc), secret.zfill(32).decode('hex'))

with open("res","w") as out:
    out.write(result)
print (result)
print ("end...")
