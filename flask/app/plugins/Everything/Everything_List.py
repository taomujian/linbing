#!/usr/bin/env python3

'''
name: Everything 敏感信息泄露漏洞
description: Everything 敏感信息泄露漏洞
'''

import re
from app.lib.utils.request import request



class Everything_List_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0'
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            req = request.get(self.url, headers = self.headers)
            title =re.findall(r"<title>(.*)</title>",req.text)[0]
            #print title
            if "Everything" in title:
                print("存在Everything 敏感信息泄露漏洞")
                return True
            else:
                print("不存在Everything 敏感信息泄露漏洞")
                return False
        except Exception as e:
            print(e)
            print("不存在Everything 敏感信息泄露漏洞")
            return False
        finally:
            pass

if  __name__ == "__main__":
    Everything_List = Everything_List_BaseVerify('http://baidu.com')
    Everything_List.run()