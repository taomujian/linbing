#!/usr/bin/env python3

import json
import asyncio
from typing import List
from fastapi import WebSocket, WebSocketDisconnect, APIRouter
from app.depend.depends import rsa_crypto, mysqldb

router = APIRouter(prefix = "/ws", tags = ["websocket"])

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
            await websocket.send_json(message)

    async def broadcast(self, message: str, exclude):
        for connection in self.active_connections:
            if connection is exclude:
                continue
            await connection.send_text(message)

manager = ConnectionManager()


@router.websocket("/target/status")
async def target_status(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = await websocket.receive_json()
        request = rsa_crypto.decrypt(request['data'])
        request = json.loads(request)
        pagenum = request['pagenum']
        pagesize = request['pagesize']
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        list_query = json.loads(request['listQuery'])
        if list_query['scan_status'] == '全部':
            list_query['scan_status'] = ''
        if list_query['scan_schedule'] == '全部':
            list_query['scan_schedule'] = ''

        username_result = mysqldb.username(query_str)

        while True:
            if username_result and username_result != 'L1001':
                sql_result = mysqldb.target_list(username_result['username'], pagenum, pagesize, list_query)
                target_list = sql_result['result']
                total = sql_result['total']
                if target_list != 'L1001' and target_list != []:
                    response['code'] = 'L1000'
                    response['message'] = '请求成功'
                    if total == 0:
                        response['data'] = ''
                    else:
                        response['data'] = sql_result
                    await manager.send_personal_message(response, websocket)

            await asyncio.sleep(5)
    except WebSocketDisconnect:
        print('Websocket连接断开')
        manager.disconnect(websocket)
    except Exception as e:
        # print(e)
        pass

@router.websocket("/scan/status")
async def scan_status(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        response = {'code': '', 'message': '', 'data': ''}
        request = await websocket.receive_json()
        request = rsa_crypto.decrypt(request['data'])
        request = json.loads(request)
        pagenum = request['pagenum']
        pagesize = request['pagesize']
        token  = request['token']
        query_str = {
            'type': 'token',
            'data': token
        }
        list_query = json.loads(request['listQuery'])
        if list_query['scan_status'] == '全部':
            list_query['scan_status'] = ''
        if list_query['scan_schedule'] == '全部':
            list_query['scan_schedule'] = ''

        username_result = mysqldb.username(query_str)

        while True:
            if username_result and username_result != 'L1001':
                sql_result = mysqldb.scan_list(username_result['username'], pagenum, pagesize, list_query)
                scan_list = sql_result['result']
                total = sql_result['total']
                if scan_list != 'L1001' and scan_list != []:
                    response['code'] = 'L1000'
                    response['message'] = '请求成功'
                    response['total'] = total
                    if total == 0:
                        response['data'] = ''
                    else:
                        response['data'] = sql_result
                    await manager.send_personal_message(response, websocket)
            await asyncio.sleep(5)
    except WebSocketDisconnect as e:
        print('Websocket连接断开')
        manager.disconnect(websocket)
    except Exception as e:
        # print(e)
        pass
