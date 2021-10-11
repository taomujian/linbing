#!/usr/bin/env python3

from app.lib.utils.request import request
from app.lib.utils.common import get_useragent

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

    def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            response1 = request.get(self.url + "/script", headers = self.headers)
            response2 = request.get(self.url +"/ajaxBuildQueue", headers = self.headers)
            if (response1.status_code==200 and "Jenkins.instance.pluginManager.plugins" in response1.text  and response2.status_code==200):
                print('存在Jenkins未授权漏洞')
                return True
            else:
                response3 = request.get(self.url +"/jenkins/script", headers = self.headers)
                response4 = request.get(self.url +"/jenkins/ajaxBuildQueue", headers = self.headers)
                if (response3.status_code==200 and "Jenkins.instance.pluginManager.plugins" in response3.text  and response4.status_code==200):
                    print('存在Jenkins未授权漏洞')
                    return True
                else:
                    print('不存在Jenkins未授权漏洞')
                    return False
        except Exception as e:
            print(e)
            print('不存在Jenkins未授权漏洞')
            return False
        finally:
            pass

if __name__ == '__main__':
    Jenkins_Unauthorized = Jenkins_Unauthorized_BaseVerify('http://127.0.0.1:8080')
    Jenkins_Unauthorized.check()