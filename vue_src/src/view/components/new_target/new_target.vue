<style lang="less">
  @import './new_target.less';
</style>

<template>
  <div class="newtarget">
    <div class="newtarget-con">
      <Card icon="log-in" title="添加目标" :bordered="false" class = card>
        <div class="form-con">
          <newtarget-form @on-success-valid="handleSubmit"></newtarget-form>
        </div>
      </Card>
    </div>
  </div>
</template>

<script>
import NewtargetForm from '_c/newtarget-form'
import RSA  from '@/libs/crypto'
import http  from '@/libs/http'
import store from '../../../store'
export default {
  components: {
    NewtargetForm
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
    handleSubmit ({ target, description, token}) {
      let data = {
        'target': target.trim(),
        'description': description.trim(),
        'token': token.trim()
      }
      data = JSON.stringify(data)
      let params = {'data': RSA.Encrypt(data)}
      http.post('/api/save', params).then((res) => {
        res.data = eval('(' + res.data + ')')
        switch(res.data.code ){
          case'Z1000':
          this.$Notice.success({
              title: '添加成功',
              desc: '请稍后在目标列表中查看'
          })
          setTimeout(() => {
            this.$router.push({
                path: '/target/list'
              })
            },5000)
          break
          case 'Z1001':
          this.$Notice.error({
              title: '添加目标失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1002':
          this.$Notice.error({
              title: '添加目标失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1004':
          this.$Notice.error({
              title: '添加目标失败',
              desc: '认证失败,请稍后再次尝试'
          })
          break
          case 'Z1008':
          this.$Notice.error({
              title: '添加目标失败',
              desc: '原密码错误,请重新输入密码再次尝试'
          })
          break
          case 'Z1020':
          this.$Notice.error({
              title: '添加的目标无法解析,请重新输入',
              desc: '添加的目标无法解析,请重新输入'
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
