from Crypto.Cipher import DES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad

def encrypt(iv, password, decr_post, salt):
    key = PBKDF2(password.encode('utf-8'), salt.encode('utf-8'), 8)
    data = decr_post.encode('utf-8')
    filling_bytes = pad(data, 16)
    aes = DES.new(key, DES.MODE_CBC, iv)
    encrypted = aes.encrypt(filling_bytes)
    return encrypted

def decrypt(iv, password, encrypted, salt):
    key = PBKDF2(password.encode('utf-8'), salt.encode('utf-8'), 8)
    filling_bytes = encrypted
    aes = DES.new(key, DES.MODE_CBC, iv)
    decrypted = aes.decrypt(filling_bytes)
    return unpad(decrypted,16).decode('utf-8')