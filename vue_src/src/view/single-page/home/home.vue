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
  mounted () {
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
