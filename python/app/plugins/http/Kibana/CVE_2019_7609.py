#!/usr/bin/env python3

import re
from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class CVE_2019_7609_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2019-7609漏洞',
            'description': 'CVE-2019-7609漏洞可执行任意命令,反弹shell, 影响范围为: Kibana < 5.6.15, < 6.6.1',
            'date': '2019-02-07',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        self.version = '9.9.9'
        self.capta = get_capta() 
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url

    async def get_kibana_version(self):
        
        """
        获取kibana版本号

        :param:

        :return:
        """
        
        headers = {
            'Referer': self.url,
            'User-Agent': get_useragent()
        }
        r = await request.get(self.url+"/app/kibana", headers = headers)
        patterns = ['&quot;version&quot;:&quot;(.*?)&quot;,', '"version":"(.*?)",']
        for pattern in patterns:
            match = re.findall(pattern, await r.text())
            if match:
                self.version = match[0]

    def version_compare(self, standard_version, compare_version):

        """
        比较目标kibana版本号是否受影响

        :param str standard_version: 被比较的版本
        :param str compare_version: 要比较的版本

        :return bool True or False: 比较的结果
        """

        sc = standard_version.split(".")
        cc = compare_version.split(".")
        if len(sc) == 3 and len(cc) == 3:
            if sc[0].isdigit() and sc[1].isdigit() and sc[2].isdigit() and cc[0].isdigit() and cc[1].isdigit() and cc[2].isdigit():
                sc_value = 100 * int(sc[0]) + 10 * int(sc[1]) + int(sc[2])
                cc_value = 100 * int(cc[0]) + 10 * int(cc[1]) + int(cc[2])
                if sc_value > cc_value:
                    return True

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        await self.get_kibana_version()
        if self.version != '9.9.9' and self.version_compare("6.6.1", self.version):
            headers = {
                'Content-Type': 'application/json;charset=utf-8',
                'Referer': self.url,
                'kbn-version': self.version,
                'User-Agent': get_useragent()
            }
            data = '{"sheet":[".es(*)"],"time":{"from":"now-1m","to":"now","mode":"quick","interval":"auto","timezone":"Asia/Shanghai"}}'
            try:
                r = await request.post(self.url + "/api/timelion/run", data = data, headers = headers)
                if r.status == 200 and 'application/json' in r.headers.get('content-type', '') and '"seriesList"' in await r.text():
                    # print("存在CVE-2019-7609漏洞")
                    return True
            except Exception as e:
                print(e)
                pass
    
if __name__ == "__main__":
    CVE_2019_7609 = CVE_2019_7609_BaseVerify('http://192.168.30.242:5601')
    CVE_2019_7609.check()