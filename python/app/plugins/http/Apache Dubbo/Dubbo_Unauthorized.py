#!/usr/bin/env python3

'''
name: Dubbo 未授权访问漏洞
description: Dubbo 未授权访问漏洞
'''

import base64
from app.lib.utils.request import request


class Dubbo_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0'
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
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
    Dubbo_Unauthorized.run()