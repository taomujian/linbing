import request from '@/utils/request'

export function scanSet(data) {
  return request({
    url: '/api/scan/set',
    method: 'post',
    data
  })
}

export function startScan(data) {
  return request({
    url: '/api/scan/start',
    method: 'post',
    data
  })
}

export function scanList(data) {
  return request({
    url: '/api/scan/list',
    method: 'post',
    data
  })
}
