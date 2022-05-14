#!/usr/bin/env python3

from app.lib.common import get_useragent
from app.lib.request import request

class Spring_Actuator_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Spring Actuator未授权漏洞',
            'description': 'Spring Actuator未授权漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Unauthorized'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            "User-Agent": get_useragent()
        }
        self.payload = ['trace','env','health','info']

    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        for i in self.payload:
            check_url  = '{}/{}'.format(self.url, i)
            try:
                req = await request.get(check_url, headers = self.headers)
                if req.headers['Content-Type'] and 'application/json' in req.headers['Content-Type'] and len(req.content)> 500:
                    # print('存在Spring Actuator未授权访问漏洞')
                    return True
            except Exception as e:
                # print(e)
                pass

if __name__ == '__main__':
    Spring_Actuator_Unauthorized = Spring_Actuator_Unauthorized_BaseVerify('http://10.4.16.3:8082/actuator')
    Spring_Actuator_Unauthorized.check()