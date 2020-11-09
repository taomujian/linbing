# 临兵漏洞扫描系统

> 本系统是对目标进行漏洞扫描的一个系统,前端采用vue技术,后端采用flask.核心原理是扫描主机的开放端口情况,然后根据端口情况逐个去进行poc检测,poc有110多个,包含绝大部分的中间件漏洞,本系统的poc皆来源于网络或在此基础上进行修改,在centons7环境下使用nginx和uwsgi部署,部署起来可能有点麻烦,烦请多点耐心,在腾讯云centos7上测试成功

## 安装python3依赖库(使用python3.8开发)

> pip3 install -r requirements.txt

> 如果你使用的是低于python3.8版本的python3,请把run.py文件中第16行注释去掉,并注释掉第17行

## 打包vue源代码(进入到vue_src目录下)

> npm run build(有打包好的,即vue文件夹,可直接使用,自行打包需要安装node和vue,参考<https://www.runoob.com/nodejs/nodejs-install-setup.html>, <https://www.runoob.com/vue2/vue-install.html>)

## 部署

### nmap

#### 安装nmap

> yum install -y nmap

### masscan

#### 安装masscan

> yum install -y masscan

### nginx

#### 安装nginx

> yum install -y nginx

#### 启动nginx

> systemctl start nginx

#### 开机自启动nginx

> systemctl enable nginx

#### 添加nginx用户

> useradd -s /sbin/nologin -M nginx

#### 配置

> 配置文件已配置好,可以直接使用,可以根据自己的需求修改文件路径及端口.
> 在/etc/nginx/conf.d目录下放入flask.conf和vue.conf文件
> 在/etc/nginx目录下放入nginx.conf文件
> conf配置文件中有注释
> 把vue目录移到/usr/share/nginx/html中
> 在flask/conf.ini中配置数据库和发送邮件设置

### mariadb

#### 安装mariadb

> yum install -y mariadb-server

#### 启动mariadb

> systemctl start mariadb

#### 设置mariadb开机自启动

> systemctl enable mariadb

#### 进行数据库配置(如设置密码等)

> mysql_secure_installation(具体步骤略去,可参考<https://www.cnblogs.com/yhongji/p/9783065.html>)
> 配置数据库密码后需要在flask/conf.ini文件中配置连接maridab数据库的用户名,密码等信息

### 邮件

> 我使用的是QQ邮箱发送的邮件,需要授权码,需要自行到flask/conf.ini文件中去设置,参考<https://blog.csdn.net/Momorrine/article/details/79881251>


### uwsgi

#### 安装uwsgi

> yum install -y postgresql-devel(debian系安装libpq-dev)

> yum install -y python3-devel(debian系安装python3-dev)

> yum install -y uwsgi uwsgi-plugin-common

#### 执行uwsgi脚本(自制uwsgi-plugin-python38, centos系统目前最高支持uwsgi-plugin-python36)

> chmod +x uwsgi.sh

> ./uwsgi.sh

#### 配置uwsgi

> 把uwsgi.ini文件放到flask文件夹的根目录下(我的flask文件夹路径是/root/flask,如果各位不是这个路径,需要到uwsgi.ini文件和flask.conf中修改文件的路径)

#### 启动uwsgi

> 进入到/root/flask/目录下,uwsgi --ini uwsgi.ini(uwsgi文件的路径)

## docker部署

### 配置

> 首先下载项目到本地(https://github.com/taomujian/linbing.git),然后配置flask/conf.ini中发送邮件所用的账号和授权码,然后修改flask/conf.ini的mysql数据库账号密码,这个账号密码要和dockerfile中的设置的账号密码保持一致

### 编译镜像(进入项目根目录)

> docker build -t linbing .

### 启动容器(进入项目根目录)

> docker run -it -d -p 11000:11000 linbing 

## 访问

> 访问<http://yourip:11000/login>即可

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
- 增加子域名详情(子域名,子域名ip),子域名是用的oneforall工具

### [v1.5] 2020.10.30
- 修改一些插件的错误
- 扫描设置中可设置POC检测时协程的并发数量
- 增加asyncio多协程功能,提高POC扫描速度

## 致谢

> 感谢vulhub项目提供的靶机环境:<https://github.com/vulhub/vulhub>,还有<https://hub.docker.com/r/2d8ru/struts2>

> POC也参考了很多项目:<https://github.com/Xyntax/POC-T>、<https://github.com/ysrc/xunfeng>、<https://github.com/se55i0n/DBScanner>、<https://github.com/vulscanteam/vulscan>

> 感谢师傅pan带我入门安全,也感谢呆橘同学在vue上对我的指导

## 免责声明

工具仅用于安全研究以及内部自查，禁止使用工具发起非法攻击，造成的后果使用者负责
