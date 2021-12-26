import request from '@/utils/request'

export function dnslogList(data) {
  return request({
    url: '/api/dns/log',
    method: 'post',
    data
  })
}

export function generateDomain(data) {
  return request({
    url: '/api/generate/domain',
    method: 'post',
    data
  })
}

export function deletednsLog(data) {
  return request({
    url: '/api/delete/dns/log',
    method: 'post',
    data
  })
}
