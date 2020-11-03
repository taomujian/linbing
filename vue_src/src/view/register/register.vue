<style lang="less">
  @import './register.less';
</style>

<template>
  <div class="register">
    <div class="register-con">
      <Card icon="log-in" title="欢迎注册" :bordered="false">
        <div class="form-con">
          <register-form @on-success-valid="handleSubmit"></register-form>
        </div>
      </Card>
    </div>
  </div>
</template>

<script>
import RegisterForm from '_c/register-form'
import RSA  from '@/libs/crypto'
import http  from '@/libs/http'
export default {
  components: {
    RegisterForm
  },
  methods: {
     handleSubmit ({ username, email, password, checknum, capta }) {
      if (checknum != capta){
        this.$Notice.error({
                title: '验证码错误',
                desc: '请重新输入验证码 '
        })
      }
      else{
        let data = {
          'username': username.trim(),
          'email': email.trim(),
          'password': password.trim()
        }
        data = JSON.stringify(data)
        let params = {'data': RSA.Encrypt(data)}
        http.post('/api/register', params).then((res) => {
          res.data = eval('(' + res.data + ')')
          switch(res.data.code ){
            case'Z1000':
            this.$Notice.success({
                title: '注册成功',
                desc: '请稍后在跳转的登录页面登录 '
            })
            setTimeout(() => {
              this.$router.push({
                path: '/login'
              })
            },5000)
            break
            case 'Z1001':
            this.$Notice.error({
                title: '注册失败',
                desc: '系统发生异常,请稍后再次尝试'
            })
            break
            case 'Z1002':
            this.$Notice.error({
                title: '注册失败',
                desc: '系统发生异常,请稍后再次尝试'
            })
            break
            default:
            break
          }
        })
      }
    },
  }
}
</script>

<style>

</style>
