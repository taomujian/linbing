#!/usr/bin/env python3

from app.lib.common import get_useragent
from app.lib.request import request

class Couchdb_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CouchDB未授权访问漏洞',
            'description': 'CouchDB未授权访问漏洞',
            'date': '',
            'exptype': 'check',
            'type': 'Unauthorized'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self. headers = {
            "User-Agent": get_useragent()
        }

    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        check_url = self.url + '/_config/'
        try:
            req = await request.get(check_url, headers = self.headers, allow_redirects = True)
            if req.status == 200 and 'httpd_design_handlers' in await req.text() and 'external_manager' in await req.text() and 'replicator_manager' in await req.text():
                # print('存在CouchDB未授权访问漏洞')
                return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    Couchdb_Unauthorized = Couchdb_Unauthorized_BaseVerify('https://github.com')
    Couchdb_Unauthorized.check()