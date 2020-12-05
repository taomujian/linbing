#!/usr/bin/env python3

'''
name: CouchDB未授权访问漏洞
description: CouchDB未授权访问漏洞
'''

from app.lib.utils.request import request

class Couchdb_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.url = url
        self. headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0"
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
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
    Couchdb_Unauthorized.run()