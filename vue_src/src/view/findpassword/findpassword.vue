<style lang="less">
  @import './findpassword.less';
</style>

<template>
  <div class="findpassword">
    <div class="findpassword-con">
      <Card icon="log-in" title="重置密码" :bordered="false">
        <div class="form-con">
          <findpassword-form @on-success-valid="handleSubmit"></findpassword-form>
        </div>
      </Card>
    </div>
  </div>
</template>

<script>
import FindpasswordForm from '_c/findpassword-form'
import RSA  from '@/libs/crypto'
import http  from '@/libs/http'
export default {
  components: {
    FindpasswordForm
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
        http.post('/api/findpassword', params).then((res) => {
          res.data = eval('(' + res.data + ')')
          switch(res.data.code ){
            case'Z1000':
            this.$Notice.success({
                title: '重置密码成功',
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
                title: '重置密码失败',
                desc: '系统发生异常,请稍后再次尝试'
            })
            break
            case 'Z1002':
            this.$Notice.error({
                title: '重置密码失败',
                desc: '系统发生异常,请稍后再次尝试'
            })
            break
            case 'Z1004':
            this.$Notice.error({
                title: '重置密码失败',
                desc: '认证失败,请重新尝试'
            })
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
