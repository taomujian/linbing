#!/usr/bin/env python3

from app.lib.common import get_useragent
from app.lib.request import request

class Jenkins_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Jenkins未授权漏洞',
            'description': 'Jenkins未授权漏洞,受影响版本: Jenkins < 2.132, the Stapler web framework < 2.121.1',
            'date': '',
            'exptype': 'check',
            'type': 'Unauthorized'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            "User-Agent": get_useragent()
        }

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            req1 = await request.get(self.url + "/script", headers = self.headers)
            req2 = await request.get(self.url +"/ajaxBuildQueue", headers = self.headers)
            if (req1.status == 200 and "Jenkins.instance.pluginManager.plugins" in await req1.text()  and req2.status==200):
                # print('存在Jenkins未授权漏洞')
                return True
            else:
                req3 = await request.get(self.url +"/jenkins/script", headers = self.headers)
                req4 = await request.get(self.url +"/jenkins/ajaxBuildQueue", headers = self.headers)
                if (req3.status==200 and "Jenkins.instance.pluginManager.plugins" in await req3.text()  and req4.status==200):
                    # print('存在Jenkins未授权漏洞')
                    return True
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    Jenkins_Unauthorized = Jenkins_Unauthorized_BaseVerify('http://127.0.0.1:8080')
    Jenkins_Unauthorized.check()