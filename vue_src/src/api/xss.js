import request from '@/utils/request'

export function logList(data) {
  return request({
    url: '/api/xss/log',
    method: 'post',
    data
  })
}

export function authList(data) {
  return request({
    url: '/api/xss/auth',
    method: 'post',
    data
  })
}

export function generateAuth(data) {
  return request({
    url: '/api/generate/auth',
    method: 'post',
    data
  })
}

export function updateAuth(data) {
  return request({
    url: '/api/update/auth',
    method: 'post',
    data
  })
}

export function deleteLog(data) {
  return request({
    url: '/api/delete/log',
    method: 'post',
    data
  })
}

export function deleteAuth(data) {
  return request({
    url: '/api/delete/auth',
    method: 'post',
    data
  })
}
