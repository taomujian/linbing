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