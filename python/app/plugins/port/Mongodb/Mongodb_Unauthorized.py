#!/usr/bin/env python3

from pymongo import MongoClient
from urllib.parse import urlparse

class Mongodb_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Mongodb 未授权访问漏洞',
            'description': 'Mongodb 未授权访问漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Unauthorized'
        }
        self.url = url
        url_parse = urlparse(self.url)
        self.host = url_parse.hostname
        self.port = url_parse.port
        if not self.port:
            self.port = '27017'

    def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            conn = MongoClient(self.host, int(self.port), socketTimeoutMS = 5000)
            dbname = conn.database_names()
            print('存在MongoDB存在未授权访问')
            return True
        except Exception as e:
            print('不存在MongoDB存在未授权访问')
            return False
        finally:
            conn.close()
            pass

if  __name__ == "__main__":
    Mongodb_Unauthorized = Mongodb_Unauthorized_BaseVerify('http://10.4.33.52:50000')
    Mongodb_Unauthorized.check()