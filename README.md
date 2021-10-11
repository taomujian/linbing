- [临兵漏洞扫描系统](#临兵漏洞扫描系统)
  - [修改加密key](#修改加密key)
    - [修改aes key](#修改aes-key)
    - [修改rsa key](#修改rsa-key)
  - [打包vue源代码(进入到vue_src目录下)](#打包vue源代码进入到vue_src目录下)
  - [ubuntu部署(强烈建议)](#ubuntu部署强烈建议)
    - [设置国内源](#设置国内源)
    - [安装依赖](#安装依赖)
    - [设置python3.8为python3](#设置python38为python3)
    - [安装python3依赖库](#安装python3依赖库)
    - [nginx](#nginx)
      - [启动nginx](#启动nginx)
      - [添加nginx用户](#添加nginx用户)
      - [配置](#配置)
    - [mariadb](#mariadb)
      - [启动mariadb](#启动mariadb)
      - [设置mariadb密码(password为你要设置的密码)](#设置mariadb密码password为你要设置的密码)
    - [redis](#redis)
      - [配置redis](#配置redis)
      - [启动redis](#启动redis)
    - [gunicorn](#gunicorn)
      - [配置gunicorn](#配置gunicorn)
      - [启动gunicorn](#启动gunicorn)
  - [centos部署](#centos部署)
    - [设置源](#设置源)
    - [安装依赖](#安装依赖-1)
    - [安装python3.8](#安装python38)
    - [安装python3依赖库](#安装python3依赖库-1)
    - [nginx](#nginx-1)
      - [启动nginx](#启动nginx-1)
      - [添加nginx用户](#添加nginx用户-1)
      - [配置](#配置-1)
    - [mariadb](#mariadb-1)
      - [启动mariadb](#启动mariadb-1)
      - [进行数据库配置(如设置密码等)](#进行数据库配置如设置密码等)
    - [redis](#redis-1)
      - [配置redis](#配置redis-1)
      - [启动redis](#启动redis-1)
    - [gunicorn](#gunicorn-1)
      - [配置gunicorn](#配置gunicorn-1)
      - [启动gunicorn](#启动gunicorn-1)
  - [自编译docker文件进行部署](#自编译docker文件进行部署)
    - [配置](#配置-2)
    - [编译镜像(进入项目根目录)](#编译镜像进入项目根目录)
    - [启动容器(进入项目根目录)](#启动容器进入项目根目录)
  - [从dockerhub中获取镜像](#从dockerhub中获取镜像)
  - [访问](#访问)
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
  - [致谢](#致谢)
  - [免责声明](#免责声明)
  - [License](#license)

# 临兵漏洞扫描系统

> 本系统是对目标进行漏洞扫描的一个系统,前端采用vue技术,后端采用python.poc有110多个,包含绝大部分的中间件漏洞,本系统的poc皆来源于网络或在此基础上进行修改

## 修改加密key

> 存储到mysql中的数据是进行aes加密后的数据,登陆请求是用的rsa请求,目前是默认的key,如果需要修改key的参考下面,修改key信息需要重新编译vue源码

### 修改aes key

> python这块直接修改/python/conf.ini中aes部分的配置即可,采用cbc模式,需要key和iv. vue部分则需要修改vue_src/src/libs/AES.js文件中第三行和第四行,要和conf.ini中保持一致

### 修改rsa key

> 需要先生成rsa的公私钥(私钥1024位)[参考地址](https://www.jianshu.com/p/d614ba4720ec)

> 修改python/rsa.py文件中的公钥和私钥信息,vue部分则需要修改vue_src/src/libs/crypto.js文件中第77行的公钥,要和python/rsa.py文件中的公钥保持一致


修改vue部分后要重新打包,然后把打包后的文件夹dist中的内容复制到vue文件夹,vue原有的文件要删除.

## 打包vue源代码(进入到vue_src目录下)

> npm run build(有打包好的,即vue文件夹,可直接使用,自行打包需要安装node和vue,参考<https://www.runoob.com/nodejs/nodejs-install-setup.html>, <https://www.runoob.com/vue2/vue-install.html>)

[ubuntu部署](##ubuntu部署(强烈建议))

[centos部署](##centos部署)

[自编译docker文件进行部署](##自编译docker文件进行部署)

[从dockerhub中获取镜像](##从dockerhub中获取镜像)

## ubuntu部署(强烈建议)

### 设置国内源

> sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list && apt-get clean && apt update

### 安装依赖

> DEBIAN_FRONTEND noninteractive apt install -y postfix

> apt install -y mariadb-server python3.8 python3.8-dev python3-pip nmap masscan nginx libpq-dev uuid-dev libcap-dev libpcre3-dev python3-dev inetutils-ping redis-server

> mkdir /root/python

### 设置python3.8为python3

> update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1 && update-alternatives --config python3

### 安装python3依赖库

> pip3 install -r /root/python/requirements.txt

> 如果你使用的是低于python3.8版本的python3,请把run.py文件中第16行注释去掉,并注释掉第17行

### nginx

#### 启动nginx

> nginx

#### 添加nginx用户

> useradd -s /sbin/nologin -M nginx

#### 配置

> gunicorn配置文件已配置好,可以直接使用,可以根据自己的需求修改文件路径及端口.conf.ini文件中配置数据库信息

> 在/etc/nginx/conf.d目录下放入vue.conf文件

> 在/etc/nginx目录下放入nginx.conf文件

> conf配置文件中有注释

> 把vue目录移到/usr/share/nginx/html中

### mariadb

#### 启动mariadb

> service mysql start

#### 设置mariadb密码(password为你要设置的密码)

> mysql -e "SET PASSWORD FOR root@localhost = PASSWORD('password');FLUSH PRIVILEGES;"

> mysql -e "update mysql.user set plugin='mysql_native_password' where User='password';FLUSH PRIVILEGES;"

> 配置数据库密码后需要在python/conf.ini文件中配置连接maridab数据库的用户名,密码等信息

### redis

#### 配置redis

> sed -i "s|bind 127.0.0.1 ::1|bind 127.0.0.1|" /etc/redis/redis.conf

> sed -i "s|# requirepass foobared|requirepass '你的redis密码'|" /etc/redis/redis.conf

> 配置数据库密码后需要在python/conf.ini文件中配置连接redis数据库的密码信息

#### 启动redis

> service redis-server start

> redis-server /etc/redis/redis.conf

### gunicorn

#### 配置gunicorn

> 把gunicorn.conf文件放到python文件夹的根目录下

#### 启动gunicorn

> 进入到/root/python/目录下,nohup gunicorn -c gunicorn.conf main:app -k uvicorn.workers.UvicornWorker > gunicorn.log 2>&1 &

## centos部署

### 设置源

> mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup && curl -o /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo && curl -o /etc/yum.repos.d/CentOS-Base.repo https://mirrors.aliyun.com/repo/Centos-7.repo && sed -i -e '/mirrors.cloud.aliyuncs.com/d' -e '/mirrors.aliyuncs.com/d' /etc/yum.repos.d/CentOS-Base.repo yum clean all && yum makecache && yum update -y

### 安装依赖

> yum install -y -q postfix

> yum install -y epel-release mariadb-server gcc gcc-c++ wget bzip2 zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel make libffi-devel nmap  masscan  nginx initscripts postgresql-devel python3-devel redis

> mkdir /root/python

### 安装python3.8

> wget https://www.python.org/ftp/python/3.8.1/Python-3.8.1.tgz 

> tar -zxvf Python-3.8.1.tgz

> cd Python-3.8.1 && ./configure prefix=/usr/local/python3.8 --enable-shared --enable-optimizations LDFLAGS="-Wl,--rpath=/usr/local/python3.8/lib" make && make install

> rm -rf /usr/bin/python3 && rm -rf /usr/bin/pip3

> ln -s /usr/local/python3.8/bin/python3.8 /usr/bin/python3 && ln -s /usr/local/python3.8/bin/pip3.8 /usr/bin/pip3

### 安装python3依赖库

> pip3 install -r /root/python/requirements.txt

> 如果你使用的是低于python3.8版本的python3,请把run.py文件中第16行注释去掉,并注释掉第17行

### nginx

#### 启动nginx

> systemctl start nginx

#### 添加nginx用户

> useradd -s /sbin/nologin -M nginx

#### 配置

> gunicorn配置文件已配置好,可以直接使用,可以根据自己的需求修改文件路径及端口.conf.ini配置数据库

> 在/etc/nginx/conf.d目录下放入vue.conf文件

> 在/etc/nginx目录下放入nginx.conf文件

> conf配置文件中有注释

> 把vue目录移到/usr/share/nginx/html中

### mariadb

#### 启动mariadb

> systemctl start mariadb

#### 进行数据库配置(如设置密码等)

> mysql_secure_installation(具体步骤略去,可参考<https://www.cnblogs.com/yhongji/p/9783065.html>)
> 配置数据库密码后需要在python/conf.ini文件中配置连接maridab数据库的用户名,密码等信息

### redis

#### 配置redis

> sed -i "s|bind 127.0.0.1 ::1|bind 127.0.0.1|" /etc/redis/redis.conf

> sed -i "s|# requirepass foobared|requirepass '你的redis密码'|" /etc/redis/redis.conf

> 配置数据库密码后需要在python/conf.ini文件中配置连接redis数据库的密码信息

#### 启动redis

> systemctl start redis

> redis-server /etc/redis.conf

### gunicorn

#### 配置gunicorn

> 把gunicorn.conf文件放到python文件夹的根目录下

#### 启动gunicorn

> 进入到/root/python/目录下,nohup gunicorn -c gunicorn.conf main:app -k uvicorn.workers.UvicornWorker > gunicorn.log 2>&1 &

## 自编译docker文件进行部署

### 配置

> 首先下载项目到本地(https://github.com/taomujian/linbing.git),然后配置python/conf.ini中发送邮件所用的账号和授权码,然后修改python/conf.ini的mysql数据库账号密码,这个账号密码要和dockerfile中的设置的账号密码保持一致

### 编译镜像(进入项目根目录)

> docker build -f ubuntu.dockerfile -t linbing .

### 启动容器(进入项目根目录)

> docker run -it -d -p 11000:11000 -p 8800:8800 linbing 

## 从dockerhub中获取镜像

> docker pull taomujian/linbing:latest

> docker run -it -d -p 11000:11000 -p 8800:8800 taomujian/linbing 

## 访问

> 访问<http://yourip:11000/login>即可,默认账号密码为admin/X!ru0#M&%V

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

###  [v2.5] 2021.7.10
- 后端框架由flask更换为fastapi

### [v2.6] 2021.9.21
- 扫描时可选择POC插件
- 增加POC列表
- 修复已知BUG

## [v2.7] 2021.10.11
- 修复扫描所有目标时的错误
- 增加XSS功能(接收数据的url参考生成token后的url)

## 致谢

> 感谢vulhub项目提供的靶机环境:

> <https://github.com/vulhub/vulhub>,

> <https://hub.docker.com/r/2d8ru/struts2>

> POC也参考了很多项目:
> 
> <https://github.com/Xyntax/POC-T>、
> 
> <https://github.com/ysrc/xunfeng>、
> 
> <https://github.com/se55i0n/DBScanner>、
> 
> <https://github.com/vulscanteam/vulscan>

> 感谢师傅pan带我入门安全,也感谢呆橘同学在vue上对我的指导

## 免责声明

工具仅用于安全研究以及内部自查，禁止使用工具发起非法攻击，造成的后果使用者负责

## License

[MIT](https://github.com/taomujian/linbing/blob/master/LICENSE)