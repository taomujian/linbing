#!/usr/bin/env python3

import base64
from app.lib.utils.request import request
from app.lib.utils.common import get_useragent

class Dubbo_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Dubbo 未授权访问漏洞',
            'description': 'Dubbo 未授权访问漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Unauthorized'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent()
        }

    def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            resp = request.get(self.url, headers = self.headers)
            if "<title>dubbo</title>" in resp.text.lower() :
                print('存在Dubbo未授权访问漏洞')
                return True
            else:
                print('不存在Dubbo未授权访问漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在Dubbo未授权访问漏洞')
            return False
        finally:
            pass

if  __name__ == "__main__":
    Dubbo_Unauthorized = Dubbo_Unauthorized_BaseVerify('http://baidu.com')
    Dubbo_Unauthorized.check()