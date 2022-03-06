## centos部署

### 设置源

> mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.backup && curl -o /etc/yum.repos.d/epel.repo <http://mirrors.aliyun.com/repo/epel-7.repo> && curl -o /etc/yum.repos.d/CentOS-Base.repo <https://mirrors.aliyun.com/repo/Centos-7.repo> && sed -i -e '/mirrors.cloud.aliyuncs.com/d' -e '/mirrors.aliyuncs.com/d' /etc/yum.repos.d/CentOS-Base.repo yum clean all && yum makecache && yum update -y

### 安装依赖

> yum install -y -q postfix

> yum install -y epel-release mariadb-server gcc gcc-c++ wget bzip2 zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel make libffi-devel nmap  masscan  nginx initscripts postgresql-devel python3-devel redis

> mkdir /root/python

### 安装python3.8

> wget <https://www.python.org/ftp/python/3.8.1/Python-3.8.1.tgz>

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