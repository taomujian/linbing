#!/usr/bin/env python3

import base64
from Crypto import Random
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from Crypto.PublicKey import RSA

class Rsa_Crypto():  
    def __init__(self):
        self.rsa_private_key = """-----BEGIN RSA PRIVATE KEY-----
        MIICXQIBAAKBgQC+UHO/FX+mqq68COGYqk82/3xw7vfhNJIM58lrjI0T+zXIx6As
        aNgrelM7Z+raDIRDJvdObz6qVbJ5L1IhcreeZWUmEtmOetqtkF4i/rhthVFmSDAK
        yZi8a6/SulpU8bHEsi2M3gyp25pi7R68GzcAmm1yKCusOaABFa4M7vuC8wIDAQAB
        AoGAd7YTmLblPOlQUGclwOogOfArTr6Cnd57oDKMuGIIu/DgvBMV5dltYKvpfwy2
        5cHJ0JPKLEQ9nteZFDF38CJA7QNfmQzZ810w/SNdP7vnhn4aFeY9/MOlZpftfMHJ
        TAAUqrOpVPTiMf5h14vAAu0idCHZJxCgSozpnJH4Kw9D9QECQQDtVv2D7GIUgtRh
        EKOM8r2YaBt89Hfb33QsyAIp+25zHDRkYcIM2lns3UgwlpmBF0ir5tZeKu9NZeKL
        13QxQIsDAkEAzUb280LR8C11ANZYr+BmagBeUOWb9c7hBxb7Pk/Pu4mGHhQSkN3Q
        WeyDB4BX+dLOaPQllvxYr7DxtHvZoGAtUQJBAJNV6VM4LzrkbMtE9QLOvfwaxNWx
        Pab09L3H++/r8gjrfWrDdR9dfW2ZgPMIyopk1exBBNq4dI3rrdN6ENtyYdkCQAvI
        kRBxu39f/KFprHmcFgTrtH5MT+GSWJSBmzZ+elw3jr1XRaGPOhCPZQ4fLe2nTjX0
        HdxG7AhZzeYgXeO44aECQQCJR8rj6X/rZQyGTHU5NPZdnC+SQB9adV8oRzy9dd4w
        P5/8M9YDDwY4JXv7sb8fH7njNpjk7DHXe9RaSED57HV6
        -----END RSA PRIVATE KEY-----
        """

        self.rsa_public_key = """-----BEGIN PUBLIC KEY-----
        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+UHO/FX+mqq68COGYqk82/3xw
        7vfhNJIM58lrjI0T+zXIx6AsaNgrelM7Z+raDIRDJvdObz6qVbJ5L1IhcreeZWUm
        EtmOetqtkF4i/rhthVFmSDAKyZi8a6/SulpU8bHEsi2M3gyp25pi7R68GzcAmm1y
        KCusOaABFa4M7vuC8wIDAQAB
        -----END PUBLIC KEY-----
        """


    def encrypt(self, content):
        """
        进行rsa加密

        :param str content: 待加密字符串
        :return: str result: 加密后的字符串
        """
        content = content.encode('utf-8')
        length = len(content)
        default_length = 117
        # 公钥加密
        pubobj = Cipher_pkcs1_v1_5.new(RSA.importKey(self.rsa_public_key))
        # 长度不用分段
        if length < default_length:
            return base64.b64encode(pubobj.encrypt(content)).decode('utf-8')
        # 需要分段
        offset = 0
        res = []
        while length - offset > 0:
            if length - offset > default_length:
                res.append(pubobj.encrypt(content[offset:offset + default_length]))
            else:
                res.append(pubobj.encrypt(content[offset:]))
            offset += default_length
        byte_data = b''.join(res)
        result = base64.b64encode(byte_data).decode('utf-8')
        return result

    def decrypt(self, content):
        
        """
        进行rsa解密

        :param str content: 待解密字符串
        :return: str result: 解密后的字符串
        """
        
        content = base64.b64decode(content)
        length = len(content)
        default_length = 128
        # 私钥解密
        priobj = Cipher_pkcs1_v1_5.new(RSA.importKey(self.rsa_private_key))
        # 长度不用分段
        if length < default_length:
            return b''.join(priobj.decrypt(content, b'xyz')).decode('utf8')
        # 需要分段
        offset = 0
        res = []
        while length - offset > 0:
            if length - offset > default_length:
                res.append(priobj.decrypt(content[offset:offset + default_length], b'xyz'))
            else:
                res.append(priobj.decrypt(content[offset:], b'xyz'))
            offset += default_length
        result = b''.join(res).decode('utf8')
        return result

if __name__ == '__main__':
    crypto = Rsa_Crypto()
    data = 'd34sdg'
    encrypt = crypto.encrypt(data)
    decrypt = crypto.decrypt(encrypt)
    print(encrypt)
    print(decrypt)




