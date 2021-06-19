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

export function pauseScan(data) {
  return request({
    url: '/api/scan/pause',
    method: 'post',
    data
  })
}

export function resumeScan(data) {
  return request({
    url: '/api/scan/resume',
    method: 'post',
    data
  })
}

export function cancelScan(data) {
  return request({
    url: '/api/scan/cancel',
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
