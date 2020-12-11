<style lang="less">
  @import './system_set.less';
</style>

<template>
  <div class="systemset">
    <div class="systemset-con">
      <Card icon="log-in" title="系统设置" :bordered="false" class = card>
        <div class="form-con">
          <systemset-form @on-success-valid="handleSubmit"></systemset-form>
        </div>
      </Card>
    </div>
  </div>
</template>

<script>
import SystemsetForm from '_c/systemset-form'
import RSA  from '@/libs/crypto'
import http  from '@/libs/http'
import store from '../../../store'
export default {
  components: {
    SystemsetForm
  },

  created() {
    // 在页面加载时读取sessionStorage里的状态信息
    if (sessionStorage.getItem('store')) {
      this.$store.replaceState(
        Object.assign(
          {},
          this.$store.state,
          JSON.parse(sessionStorage.getItem('store'))
        )
      )
    }
 
    // 在页面刷新时将vuex里的信息保存到sessionStorage里
    // beforeunload事件在页面刷新时先触发
    window.addEventListener('beforeunload', () => {
      sessionStorage.setItem('store', JSON.stringify(this.$store.state))
    })
  },
  
  methods: {
    handleSubmit ({ proxytype, proxyip, timeout, token}) {
      console.log(proxytype, proxyip, timeout, token)
      let data = {
        'proxytype': proxytype.trim(),
        'proxyip': proxyip.trim(),
        'timeout': timeout.trim(),
        'token': token.trim()
      }
      data = JSON.stringify(data)
      let params = {'data': RSA.Encrypt(data)}
      http.post('/api/system_set', params).then((res) => {
        res.data = eval('(' + res.data + ')')
        switch(res.data.code ){
          case'Z1000':
          this.$Notice.success({
              title: '设置成功',
              desc: '稍后返回系统设置页面'
          })
          setTimeout(() => {
            this.$router.push({
                path: '/system'
              })
            },5000)
          break
          case 'Z1001':
          this.$Notice.error({
              title: '设置失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1002':
          this.$Notice.error({
              title: '设置失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1004':
          this.$Notice.error({
              title: '设置失败',
              desc: '认证失败,请稍后再次尝试'
          })
          break
          case 'Z1008':
          this.$Notice.error({
              title: '设置失败',
              desc: '原密码错误,请重新输入密码再次尝试'
          })
          break
          case 'Z1020':
          this.$Notice.error({
              title: '设置失败,请重新输入',
              desc: '设置失败,请重新输入'
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
