<template>
  <div>
    <Row :gutter="20" style="margin-top: 50px;margin-left: 500px;">
      <i-col :md="24" :lg="8" >
        <Card shadow >
          <span class = "title">欢迎登录</span>
        </Card>
      </i-col>
    </Row>
  </div>
</template>

<script>
export default {
  name: 'home',
  data () {
    return {}
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
  }
}
</script>

<style>
.card{
  text-align:center;
}

.title{
  font-size: 50px;
  text-align:center ;
}
</style>
