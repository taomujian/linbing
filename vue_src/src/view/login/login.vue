<style lang="less">
  @import './login.less';
</style>

<template>
  <div class="login">
    <div class="login-con">
      <Card icon="log-in" title="欢迎登录" :bordered="false">
        <div class="form-con">
          <login-form @on-success-valid="handleSubmit"></login-form>
        </div>
      </Card>
    </div>
  </div>
</template>

<script>
import http from '@/libs/http'
import LoginForm from '_c/login-form'
import RSA from '@/libs/crypto'
import store from '../../store'
export default {
  components: {
    LoginForm
  },
  methods: {
    handleSubmit ({ username, password }) {
      let data = {
        'username': username.trim(),
        'password': password.trim()
      }
      data = JSON.stringify(data)
      let params = {'data': RSA.Encrypt(data)}
      http.post('/api/login', params).then((res) => {
        res.data = eval('(' + res.data + ')')
        switch(res.data.code ){
          case'Z1000':
          store.commit('setToken', res.data.data.token)
          let data = {
            'token': res.data.data.token.trim()
          }
          data = JSON.stringify(data)
          let params = {'data': RSA.Encrypt(data)}
          http.post('/api/getuserinfo', params).then((res) => {
            res.data = eval('(' + res.data + ')')
            switch(res.data.code ){
              case'Z1000':
              this.$Notice.success({
                  title: '登录成功',
                  desc: '马上跳转到主页 '
              })
              store.commit('setUserName', res.data.data.username)
              store.commit('setUserEmail', res.data.data.email)
              store.commit('setAvatar', '/api/images/'+ res.data.data.avatar)
              store.commit('setAccess',res.data.data.access)
              store.commit('setUserId', res.data.data.user_id)
              store.commit('setHasGetInfo', true)

              setTimeout(() => {
                this.$router.push({
                  path: '/home'
                })
              },1000)
              break

              case 'Z1001':
              this.$Notice.error({
                  title: '登录失败',
                  desc: '系统发生异常,请稍后再次尝试'
              })
              break

              case 'Z1002':
              this.$Notice.error({
                  title: '登录失败',
                  desc: '系统发生异常,请稍后再次尝试'
              })
              break

              case 'Z1004':
              this.$Notice.error({
                  title: '登录失败',
                  desc: '登录失败,原因是认证失败,请重新登录'
              })
              break
            }
          })
          break

          case 'Z1001':
          this.$Notice.error({
              title: '登录失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break

          case 'Z1002':
          this.$Notice.error({
              title: '登录失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break

          case 'Z1005':
          this.$Notice.error({
              title: '用户未注册',
              desc: '请前往注册页面注册'
          })
          break

          case 'Z1008':
          this.$Notice.error({
              title: '密码错误',
              desc: '密码错误,如果忘记密码请找回密码'
          })
          default:
          break
        }
      })
    },
  }
}
</script>

<style>

</style>
