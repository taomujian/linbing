#!/usr/bin/env python3

'''
用于各种编码功能
'''

import urllib
import base64
import hashlib

def md5(data):
    
    """
    对字符串进行md5哈希

    :param str data: 需要哈希的字符串
    :return str result: 哈希后的字符串
    """
    result = hashlib.md5(data.encode()).hexdigest()
    return result

def urlencode(data, encode_type = 'part'):
    
    """
    根据类型选择对部分或者全部字符进行url编码

    :param str data: 需要编码的字符串
    :param str encode_type: 选择对部分还是全部字符进行url编码
    :return str return_str: url编码后的字符串
    """
    if encode_type == 'total':
        data = data.encode('utf-8')
        data = ''.join('%{:02X}'.format(x) for x in data)
        return data
    else:
        return urllib.parse.quote(data)

def base64encode(data):
    
    """
    对字符进行base64编码

    :param str data: 需要编码的字符串
    :return str return_str: base64编码后的字符串
    """

    data = data.encode('utf-8')
    data = base64.b64encode(data).decode('utf-8')
    return data
