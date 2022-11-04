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
    url: '/api/dns/generate/domain',
    method: 'post',
    data
  })
}

export function deletednsLog(data) {
  return request({
    url: '/api/dns/log/delete',
    method: 'post',
    data
  })
}
