#!/usr/bin/env python3

from app.lib.utils.request import request
from app.lib.utils.common import get_useragent

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

    def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        check_url = self.url + '/_config/'
        try:
            req = request.get(check_url, headers = self.headers, allow_redirects = True)
            if req.status_code == 200 and 'httpd_design_handlers' in req.text and 'external_manager' in req.text and 'replicator_manager' in req.text:
                print('存在CouchDB未授权访问漏洞')
                return True
            else:
                print('不存在CouchDB未授权访问漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在CouchDB未授权访问漏洞')
            return False
        finally:
            pass

if  __name__ == "__main__":
    Couchdb_Unauthorized = Couchdb_Unauthorized_BaseVerify('https://github.com')
    Couchdb_Unauthorized.check()