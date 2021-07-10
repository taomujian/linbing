import request from '@/utils/request'

export function login(data) {
  return request({
    url: '/api/login',
    method: 'post',
    data
  })
}

export function getInfo(data) {
  return request({
    url: '/api/userinfo',
    method: 'post',
    data
  })
}

export function changeAvatar(data) {
  return request({
    url: '/api/change/avatar',
    method: 'post',
    data
  })
}

export function uploadImage(data) {
  return request({
    url: '/api/upload/image',
    method: 'post',
    data
  })
}

export function changePassword(data) {
  return request({
    url: '/api/change/password',
    method: 'post',
    data
  })
}

export function queryPassword(data) {
  return request({
    url: '/api/query/password',
    method: 'post',
    data
  })
}

export function logout(data) {
  return request({
    url: '/api/logout',
    method: 'post',
    data
  })
}
