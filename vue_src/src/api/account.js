import request from '@/utils/request'

export function accountList(data) {
  return request({
    url: '/api/account/list',
    method: 'post',
    data
  })
}

export function accountAdd(data) {
  return request({
    url: '/api/account/add',
    method: 'post',
    data
  })
}

export function queryAccount(data) {
  return request({
    url: '/api/query/account',
    method: 'post',
    data
  })
}

export function accountRole(data) {
  return request({
    url: '/api/account/role',
    method: 'post',
    data
  })
}

export function accountPassword(data) {
  return request({
    url: '/api/account/password',
    method: 'post',
    data
  })
}

export function accountDescription(data) {
  return request({
    url: '/api/account/description',
    method: 'post',
    data
  })
}

export function deleteAccount(data) {
  return request({
    url: '/api/delete/account',
    method: 'post',
    data
  })
}
