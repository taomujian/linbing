<style lang="less">
  @import './changepassword.less';
</style>

<template>
  <div class="changepassword">
    <div class="changepassword-con">
      <Card icon="log-in" title="修改密码" :bordered="false" class = card>
        <div class="form-con">
          <changepassword-form @on-success-valid="handleSubmit"></changepassword-form>
        </div>
      </Card>
    </div>
  </div>
</template>

<script>
import ChangepasswordForm from '_c/changepassword-form'
import RSA  from '@/libs/crypto'
import http  from '@/libs/http'
import store from '../../store'
export default {
  components: {
    ChangepasswordForm
  },
  methods: {
    handleSubmit ({ oldpassword, newpassword, token}) {
      let data = {
        'oldpassword': oldpassword.trim(),
        'newpassword': newpassword.trim(),
        'token': token.trim()
      }
      data = JSON.stringify(data)
      let params = {'data': RSA.Encrypt(data)}
      http.post('/api/changepassword', params).then((res) => {
        res.data = eval('(' + res.data + ')')
        switch(res.data.code ){
          case'Z1000':
          this.$Notice.success({
              title: '修改成功',
              desc: '请稍后在跳转的登录页面登录'
          })
          setTimeout(() => {
            store.commit('setToken', '')
            this.$router.push({
                path: '/login'
              })
            },4000)
          break
          case 'Z1001':
          this.$Notice.error({
              title: '修改密码失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1002':
          this.$Notice.error({
              title: '修改密码失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1004':
          this.$Notice.error({
              title: '修改密码失败',
              desc: '认证失败,请稍后再次尝试'
          })
          break
          case 'Z1008':
          this.$Notice.error({
              title: '修改密码失败',
              desc: '原密码错误,请重新输入密码再次尝试'
          })
          break
          default:
          break
        }
      })
    }
  }
}
</script>

<style>

</style>
