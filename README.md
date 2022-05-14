- [临兵漏洞扫描系统](#临兵漏洞扫描系统)
  - [使用说明](#使用说明)
  - [修改加密key](#修改加密key)
    - [修改aes key](#修改aes-key)
    - [修改rsa key](#修改rsa-key)
  - [打包vue源代码(进入到vue_src目录下)](#打包vue源代码进入到vue_src目录下)
  - [ubuntu部署](#ubuntu部署)
  - [centos部署](#centos部署)
  - [自编译docker文件进行部署](#自编译docker文件进行部署)
    - [配置](#配置)
    - [编译镜像(进入项目根目录)](#编译镜像进入项目根目录)
    - [启动容器(进入项目根目录)](#启动容器进入项目根目录)
  - [从dockerhub中获取镜像](#从dockerhub中获取镜像)
  - [访问](#访问)
  - [界面](#界面)
  - [CHANGELOG](#changelog)
    - [[v1.0] 2020.2.28](#v10-2020228)
    - [[v1.1] 2020.7.28](#v11-2020728)
    - [[v1.2] 2020.8.12](#v12-2020812)
    - [[v1.3] 2020.9.13](#v13-2020913)
    - [[v1.4] 2020.10.18](#v14-20201018)
    - [[v1.5] 2020.10.30](#v15-20201030)
    - [[v1.6] 2020.11.27](#v16-20201127)
    - [[v1.7] 2020.12.5](#v17-2020125)
    - [[v1.8] 2020.12.11](#v18-20201211)
    - [[v1.9] 2020.12.18](#v19-20201218)
    - [[v2.0] 2021.3.1](#v20-202131)
    - [[v2.1] 2021.3.5](#v21-202135)
    - [[v2.2] 2021.3.26](#v22-2021326)
    - [[v2.3] 2021.5.20](#v23-2021520)
    - [[v2.4] 2021.6.19](#v24-2021619)
    - [[v2.5] 2021.7.10](#v25-2021710)
    - [[v2.6] 2021.9.21](#v26-2021921)
    - [[v2.7] 2021.10.11](#v27-20211011)
    - [[v2.8] 2021.10.24](#v28-20211024)
    - [[v2.9] 2021.12.26](#v29-20211226)
    - [[v3.0] 2022.5.14](#v30-2022514)
  - [致谢](#致谢)
  - [免责声明](#免责声明)
  - [License](#license)

# 临兵漏洞扫描系统

> 本系统是对Web中间件和Web框架进行自动化渗透的一个系统,根据扫描选项去自动化收集资产,然后进行POC扫描,POC扫描时会根据指纹选择POC插件去扫描,POC插件扫描用异步方式扫描.前端采用vue技术,后端采用python fastapi.

## 使用说明

> 扫描分为指纹探测、子域名爆破、端口扫描、目录扫描、POC扫描.如果选择所有扫描选项,子域名扫出的IP会传给端口扫描,端口扫描中识别指纹,扫描出的资产传给目录扫描和POC扫描,POC扫描会根据资产指纹去加载插件扫描,如果识别不到指纹,则加载所有插件,POC插件分为2种类型,http和port,http类型指发送http请求,port指发送socket请求,扫描出的资产如果是url格式,则加载http类型插件,否则则加载port类型插件.

## 修改加密key

> 存储到mysql中的数据是进行aes加密后的数据,登陆请求是用的rsa请求,目前是默认的key,如果需要修改key的参考下面,修改key信息需要重新编译vue源码

### 修改aes key

> python这块直接修改/python/conf.ini中aes部分的配置即可,采用cbc模式,需要key和iv. vue部分则需要修改vue_src/src/libs/AES.js文件中第三行和第四行,要和conf.ini中保持一致

### 修改rsa key

> 需要生成rsa的公私钥(私钥1024位)[参考地址](https://www.jianshu.com/p/d614ba4720ec)
> 修改python/rsa.py文件中的公钥和私钥信息,vue部分则需要修改vue_src/src/libs/crypto.js文件中第77行的公钥,要和python/rsa.py文件中的公钥保持一致

修改vue部分后要重新打包,然后把打包后的文件夹dist中的内容复制到vue文件夹,vue原有的文件要删除.

## 打包vue源代码(进入到vue_src目录下)

> npm run build(有打包好的,即vue文件夹,可直接使用,自行打包需要安装node和vue,参考<https://www.runoob.com/nodejs/nodejs-install-setup.html>, <https://www.runoob.com/vue2/vue-install.html>)

[ubuntu部署](##ubuntu部署(强烈建议))

[centos部署](##centos部署)

[自编译docker文件进行部署](##自编译docker文件进行部署)

[从dockerhub中获取镜像](##从dockerhub中获取镜像)

## ubuntu部署

> 参考<https://github.com/taomujian/linbing/blob/master/ubuntu部署.md>)

## centos部署

> 参考<https://github.com/taomujian/linbing/blob/master/centos部署.md>)

## 自编译docker文件进行部署

### 配置

> 首先下载项目到本地(<https://github.com/taomujian/linbing.git),然后配置python/conf.ini中发送邮件所用的账号和授权码,然后修改python/conf.ini的mysql数据库账号密码,这个账号密码要和dockerfile>中的设置的账号密码保持一致

### 编译镜像(进入项目根目录)

> docker build -f ubuntu.dockerfile -t linbing .

### 启动容器(进入项目根目录)

> docker run -it -d -p 11000:11000 -p 8800:8800 linbing

## 从dockerhub中获取镜像

> docker pull taomujian/linbing:latest
> docker run -it -d -p 11000:11000 -p 8800:8800 taomujian/linbing

## 访问

> 访问<http://yourip:11000/login>即可,默认账号密码为admin/X!ru0#M&%V

## 界面

![登录.jpg](https://github.com/taomujian/linbing/raw/master/images/登录.jpg)

![首页.jpg](https://github.com/taomujian/linbing/raw/master/images/首页.jpg)

![目标.jpg](https://github.com/taomujian/linbing/raw/master/images/目标.jpg)

![扫描.jpg](https://github.com/taomujian/linbing/raw/master/images/扫描.jpg)

![POC.jpg](https://github.com/taomujian/linbing/raw/master/images/POC.jpg)

## CHANGELOG

### [v1.0] 2020.2.28

- 初步完成扫描器功能

### [v1.1] 2020.7.28

- 新增F5 BIG IP插件

### [v1.2] 2020.8.12

- 增加docker部署

### [v1.3] 2020.9.13

- 增加phpstudy_back_rce插件数量
- 添加目标时可添加多行目标

### [v1.4] 2020.10.18

- 增加查看端口详情(端口、协议、产品、版本)
- 增加子域名详情(子域名,子域名ip),子域名是用的OneForAll工具

### [v1.5] 2020.10.30

- 修改一些插件的错误
- 扫描设置中可设置POC检测时协程的并发数量
- 增加asyncio多协程功能,提高POC扫描速度

### [v1.6] 2020.11.27

- 修改默认头像,若想替换的话直接flask/images/default.png图片就可以了
- 优化前端修复一些小BUG

### [v1.7] 2020.12.5

- 增加设置代理和扫描的超时时间功能
- 优化前端修复一些小BUG
- 优化文件结构,同步docker时间

### [v1.8] 2020.12.11

- 优化前端刷新后头像丢失BUG

### [v1.9] 2020.12.18

- 修改发送邮件的方式,使用postfix发送邮件

### [v2.0] 2021.3.1

- 前端ui框架由iview换为element,重构前端代码
- 取消账号注册,改由内置管理员账号添加
- 增加对url目标的目录扫描功能
- 增加查看所有漏洞和所有端口信息的功能
- 优化数据库表格数据结构和sql语句

### [v2.1] 2021.3.5

- 前端界面优化
- 多个目标扫描同时扫描时,增加任务队列管理

### [v2.2] 2021.3.26

- 增加CVE-2021-22986插件

### [v2.3] 2021.5.20

- 优化扫描逻辑
- 增加指纹探测,探测使用的框架
- 优化Struts2 系列漏洞的检测

### [v2.4] 2021.6.19

- 增加指纹判断功能
- 对扫出来的端口进行指纹识别,指纹识别后去加载对应的插件,减少发包数量
- 对插件进行分类,分为http类和非http类
- 点击扫描时提供自定义扫描选项功能,分为指纹探测, 子域名扫描, 端口扫描, 目录扫描, POC扫描
- 扫描列表中增加暂停扫描、恢复扫描、取消扫描功能

### [v2.5] 2021.7.10

- 后端框架由flask更换为fastapi

### [v2.6] 2021.9.21

- 扫描时可选择POC插件
- 增加POC列表
- 修复已知BUG

### [v2.7] 2021.10.11

- 修复扫描所有目标时的错误
- 增加XSS LOG功能(接收数据的url参考生成token后的url)

### [v2.8] 2021.10.24

- 目标管理和扫描管理中状态信息更新由Ajax轮询换成websocket

### [v2.9] 2021.12.26

- 集成dnslog.cn的功能,提供dnslog功能

### [v3.0] 2022.5.14

- POC插件扫描换成异步扫描方式,加快扫描速度

## 致谢

> 感谢vulhub项目提供的靶机环境:
> <https://github.com/vulhub/vulhub>,
> <https://hub.docker.com/r/2d8ru/struts2>
>
> POC也参考了很多项目:
> <https://github.com/Xyntax/POC-T>、
>
> <https://github.com/ysrc/xunfeng>、
>
> <https://github.com/se55i0n/DBScanner>、
>
> <https://github.com/vulscanteam/vulscan>
> 
> 感谢师傅pan带我入门安全,也感谢呆橘同学在vue上对我的指导

## 免责声明

工具仅用于安全研究以及内部自查，禁止使用工具发起非法攻击，造成的后果使用者负责

## License

[MIT](https://github.com/taomujian/linbing/blob/master/LICENSE)