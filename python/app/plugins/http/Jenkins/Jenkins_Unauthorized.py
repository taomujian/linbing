#!/usr/bin/env python3

'''
name: Jenkins未授权漏洞
description: Jenkins未授权漏洞
'''

from app.lib.utils.request import request


class Jenkins_Unauthorized_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
        }

    def run(self):
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
    Jenkins_Unauthorized.run()