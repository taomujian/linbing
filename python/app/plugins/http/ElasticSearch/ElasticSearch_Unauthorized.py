#!/usr/bin/env python3

from app.lib.common import get_useragent
from app.lib.request import request

class ElasticSearch_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'ElasticSearch 未授权访问漏洞',
            'description': 'ElasticSearch 未授权访问漏洞',
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

    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            req = await request.get(self.url + '/_cat', headers = self.headers)
            result = await req.text()
            if '/_cat/master' in result.lower() :
                # print('存在ElasticSearch未授权访问漏洞')
                return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    ElasticSearch_Unauthorized = ElasticSearch_Unauthorized_BaseVerify('http://127.0.0.1:9200')
    ElasticSearch_Unauthorized.check()