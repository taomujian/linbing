# POC种类

> POC主要分为2类,一类是Web型,这种POC适合目标是Web服务.另一类是PORT型,这种POC适合目标是TCP/UDP服务.

# POC路径

> Web类型的POC路径为python/app/plugins/http

> PORT类型的POC路径为python/app/plugins/port

# 添加POC

> 假设新增一个Apache SDFTG中间件(实际并不存在)的漏洞CVE-2025-1567(实际并不存在,为虚构)

> 新增的POC文件名为CVE_2025_1567.py,新建python/app/plugins/http/Apache SDFTG 目录,把CVE_2025_1567.py放到python/app/plugins/http/Apache SDFTG 目录

> CVE_2025_1567.py文件内容为下

```python
#!/usr/bin/env python3

from app.lib.request import request
from app.lib.common import get_capta, get_useragent

class CVE_2025_1567_BaseVerify:
    def __init__(self, url):
        self.info = {
            'name': 'CVE-2025-1567漏洞',
            'description': 'CVE-2025-1567漏洞可执行任意命令,影响范围为: Apache SDFTG < 7.1',
            'date': '2025-08-07',
            'exptype': 'check',
            'type': 'RCE'
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

        url = self.url + '/demo/update'
        try:
            req = await request.get(url, headers = self.headers)
            req_result = await req.json()
            if req_result['responseHeader']['status'] == 0:
                return True
        except Exception as e:
            # print(e)
            pass

if  __name__ == "__main__":
    CVE_2025_1567 = CVE_2025_1567_BaseVerify('http://127.0.0.1:8983')
    CVE_2025_1567.check()
```

> from app.lib.request import request 这是获取封装好的aiohttp请求,也可以直接使用其他的库,就是设置的Web代理将无法工作

> from app.lib.common import get_capta, get_useragent, get_capta是用来获取随机字符的函数,get_useragent用来随机获取一个请求的user-agent头

> class CVE_2025_1567_BaseVerify是类名,每一个POC文件内容都是由一个类组成,类的名字组成规则是POC的文件名_BaseVerify,这个必须要注意,必须按照这样的规则来,否则无法加载.在初始化类时,要把url参数传递过来,

> self.info是一些漏洞信息,name是漏洞信息,description是漏洞描述,date是漏洞出现日期,exptype表明这是个POC,exptype的值一般为'POC',只能用来验证漏洞是否存在,type表明这个漏洞是RCE类型的漏洞.

> 每个POC都必须含有一个check函数,用来进行具体的漏洞检测处理逻辑.如果达到存在漏洞的条件,就要返回True,不存在不需要任何处理.

> 这样一个漏洞的POC就添加完了