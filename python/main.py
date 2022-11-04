#!/usr/bin/env python3

import uvicorn
from passlib.context import CryptContext
from app.lib.common import get_capta
from fastapi import FastAPI, Request, APIRouter
from app.depend.depends import  mysqldb, aes_crypto
from app.router import user, account, home, poc, target, vulner, scan, system, websocket, xss, dns, port

app = FastAPI()

mysqldb.create_database('linbing')
mysqldb.create_user()
mysqldb.create_port()
mysqldb.create_vulner()
mysqldb.create_poc()
mysqldb.create_target()
mysqldb.create_target_scan()
mysqldb.create_target_domain()
mysqldb.create_target_port()
mysqldb.create_target_path()
mysqldb.create_target_vulner()
mysqldb.create_cms_finger()
mysqldb.create_fofa_cms_finger()
mysqldb.create_xss_log()
mysqldb.create_dns_log()
mysqldb.create_xss_auth()
mysqldb.init_finger('cms_finger.db')
mysqldb.init_poc()

random_str = get_capta()
token = aes_crypto.encrypt('admin' + random_str)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
mysqldb.save_account('admin', '系统内置管理员,不可删除,不可修改', token, pwd_context.hash('X!ru0#M&%V'), 'admin', 'avatar.png')

root_router = APIRouter(prefix = "/api", tags = ["api"])
root_router.include_router(user.router)
root_router.include_router(account.router)
root_router.include_router(home.router)
root_router.include_router(poc.router)
root_router.include_router(port.router)
root_router.include_router(target.router)
root_router.include_router(vulner.router)
root_router.include_router(scan.router)
root_router.include_router(xss.router)
root_router.include_router(dns.router)
root_router.include_router(system.router)
root_router.include_router(websocket.router)

app = FastAPI()
app.include_router(root_router)

@app.get('/log')
async def log(token: str, data: str, request: Request):
    
    """
    接收xss log的接口

    :param:
    :return:
    """

    try:
        username = mysqldb.xss_username(token)
        if username:
            path = '/api/log?' + str(request.query_params)
            ip = request.client.host
            if 'user-agent' in  request.headers.keys():
                ua = request.headers['user-agent']
            mysqldb.save_xss_log(username, path, data, ua, ip)
    except Exception as e:
        print(e)


if __name__ == '__main__':
    # uvicorn.run(app = 'main:app', host = '0.0.0.0', port = 5000, reload = True, log_level = 'debug')
    uvicorn.run(app = 'main:app', host = '0.0.0.0', port = 8000, reload = False, log_level = 'debug')
