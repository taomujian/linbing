import axios from 'axios'
import { Notification } from 'element-ui'
import store from '@/store'
import { getToken } from '@/utils/auth'

// create an axios instance
const service = axios.create({
  // baseURL: process.env.VUE_APP_BASE_API, // url = base url + request url
  baseURL: '',
  withCredentials: true, // send cookies when cross-domain requests
  timeout: 60000 // request timeout
})

// request interceptor
service.interceptors.request.use(
  config => {
    // do something before request is sent
    config.headers['Content-Type'] = 'application/json'
    if (store.getters.token) {
      config.headers['token'] = getToken()
    }
    return config
  },
  error => {
    // do something with request error
    console.log(error) // for debug
    return Promise.reject(error)
  }
)

// response interceptor
service.interceptors.response.use(
  /**
   * If you want to get http information such as headers or status
   * Please return  response => response
  */

  /**
   * Determine the request status by custom code
   * Here is just an example
   * You can also judge the status by HTTP Status Code
   */
  response => {
    const res = response.data
    // if the custom code is not 20000, it is judged as an error.
    if (res.code === 'L1001') {
      Notification({
        title: '请求失败',
        message: '系统异常,请稍后重新尝试!',
        type: 'error',
        duration: 3 * 1000
      })

      // 50008: Illegal token; 50012: Other clients logged in; 50014: Token expired;
      /* if (res.code === 'L1004' || res.code === 50012 || res.code === 50014) {
        // to re-login
        NotificationBox.confirm('You have been logged out, you can cancel to stay on this page, or log in again', 'Confirm logout', {
          confirmButtonText: 'Re-Login',
          cancelButtonText: 'Cancel',
          type: 'warning'
        }).then(() => {
          store.dispatch('user/resetToken').then(() => {
            location.reload()
          })
        })
      }*/
      return Promise.reject(new Error('系统异常,请稍后重新尝试!'))
    } else if (res.code === 'L1002') {
      Notification({
        title: '请求失败',
        message: '请求方法异常,请正常操作!',
        type: 'error',
        duration: 3 * 1000
      })
      return Promise.reject(new Error('请求方法异常,请正常操作!'))
    } else if (res.code === 'L1003') {
      Notification({
        title: '请求失败',
        message: '认证失败,请重新登录操作!',
        type: 'error',
        duration: 3 * 1000
      })
      store.dispatch('user/resetToken').then(() => {
        location.reload()
      })
    } else if (res.code === 'L1004') {
      Notification({
        title: '请求失败',
        message: '用户不存在,请使用管理员账号添加该用户!',
        type: 'error',
        duration: 3 * 1000
      })
      return Promise.reject(new Error('用户不存在,请使用管理员账号添加该用户!'))
    } else if (res.code === 'L1005') {
      Notification({
        title: '请求失败',
        message: '用户已存在,请添加其它用户!',
        type: 'error',
        duration: 3 * 1000
      })
      return Promise.reject(new Error('用户已存在,请添加其它用户!'))
    } else if (res.code === 'L1006') {
      Notification({
        title: '请求失败',
        message: res.message,
        type: 'error',
        duration: 3 * 1000
      })
      return Promise.reject(new Error(res.message))
    } else if (res.code === 'L1007') {
      Notification({
        title: '请求失败',
        message: '密码错误,请输入正确密码!',
        type: 'error',
        duration: 3 * 1000
      })
      return Promise.reject(new Error('密码错误,请输入正确密码!'))
    } else if (res.code === 'L1008') {
      Notification({
        title: '请求成功',
        message: '文件上传成功!',
        type: 'success',
        duration: 3 * 1000
      })
      return res
    } else if (res.code === 'L1009') {
      Notification({
        title: '密码错误',
        message: '旧密码输入错误',
        type: 'error',
        duration: 3 * 1000
      })
      return Promise.reject(new Error('旧密码输入错误'))
    } else if (res.code === 'L10010') {
      Notification({
        title: '权限不足',
        message: '权限不足,无法进行操作',
        type: 'error',
        duration: 3 * 1000
      })
      return Promise.reject(new Error('权限不足,无法进行操作'))
    } else {
      return res
    }
  },
  error => {
    console.log('err' + error) // for debug
    Notification({
      title: '请求失败',
      message: error.message,
      type: 'error',
      duration: 3 * 1000
    })
    return Promise.reject(error)
  }
)

export default service
