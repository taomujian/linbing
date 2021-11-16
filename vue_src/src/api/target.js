import request from '@/utils/request'

export function newTarget(data) {
  return request({
    url: '/api/target/new',
    method: 'post',
    data
  })
}

export function queryTarget(data) {
  return request({
    url: '/api/query/target',
    method: 'post',
    data
  })
}

export function editTarget(data) {
  return request({
    url: '/api/target/edit',
    method: 'post',
    data
  })
}

export function targetDetail(data) {
  return request({
    url: '/api/target/detail',
    method: 'post',
    data
  })
}

export function targetList(data) {
  return request({
    url: '/api/target/list',
    method: 'post',
    data
  })
}

export function deleteTarget(data) {
  return request({
    url: '/api/delete/target',
    method: 'post',
    data
  })
}
