<template>
  <div class = "div">
    <Row>
    <Col span="18" offset="2">
          <Card class = "card1">
              <p slot="title">扫描端口范围</p>
              <span class = "zuixiao">最小值</span>
              <InputNumber :max="65535" :min="1" v-model="min" class = "min"></InputNumber>
              <span class = "zuida">最大值</span>
              <InputNumber :max="65535" :min="1" v-model="max" class = "max"></InputNumber>
          </Card>
      </Col>
      <Col span="18" offset="2">
          <Card class = "card2">
              <p slot="title">扫描器选择</p>
              <RadioGroup v-model="scanner">
                <Radio label="nmap" class = "nmap"></Radio>
                <Radio label="masscan" class = "masscan"></Radio>
              </RadioGroup>
          </Card>
      </Col>
      <Col span="18" offset="2">
          <Card class = "card3">
              <p slot="title">POC协程数量</p>
              <Input v-model="concurren_number" placeholder="POC检测时协程的并发数量"/>
          </Card>
      </Col>
      <div v-if="scanner === 'masscan'">
        <Col span="18" offset="2">
          <Card class = "card3">
              <p slot="title">扫描速率</p>
              <span class = "zuixiao">扫描速率</span>
              <InputNumber :max="1000000000" :min="1" v-model="rate" class = "rate"></InputNumber>
          </Card>
        </Col>
      </div>
      <Button @click="handleSubmit" type="primary" long class = "button">确定</Button>
    </Row>
  </div>
</template>

<script>
import RSA  from '@/libs/crypto'
import http  from '@/libs/http'
import {getToken } from '@/libs/util'
export default {
  inject: ['reload'],
  name: 'tables_page',
  data () {
    return {
      target: '',
      min: 1,
      max: 65535,
      scanner: 'nmap',
      rate: 1000,
      concurren_number: '50'
    }
  },

  created() {
    this.$nextTick(this.getParams())
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
    getParams () {
      this.target = this.$route.query.params
    },

    handleSubmit (params) {
      let data = {
        'target': this.target,
        'token': getToken(),
        'scanner': this.scanner,
        'min_port': this.min + '',
        'max_port': this.max + '',
        'rate': this.rate + '',
        'concurren_number': this.concurren_number
      }
      data = JSON.stringify(data)
      let req_params = {'data': RSA.Encrypt(data)}
      http.post('/api/scan_set', req_params).then((res) => {
        res.data = eval('(' + res.data + ')')
        switch(res.data.code ){
          case'Z1000':
          this.$Notice.success({
              title: '已设置扫描',
              desc: '请稍后在目标列表中开始扫描'
          })
          setTimeout(() => {
            this.$router.push({
                path: '/target/list'
              })
            },5000)
          break
          case 'Z1001':
          this.$Notice.error({
              title: '请求失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1002':
          this.$Notice.error({
              title: '请求失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1004':
          this.$Notice.error({
              title: '请求失败',
              desc: '认证失败,请稍后再次尝试'
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
  .card1{
    bottom: -20px;
  }
  .card2{
    bottom: -60px;
  }
  .card3{
    bottom: -100px;
  }
  .nmap{
    width: 20%;
    left: 140%;
  }
  .masscan{
    width: 20%;
    left: 352%;
  }
  .button{
    width: 10%;
    margin-top: 30%;
    height: 30px;
    margin-left: -50%;
    float: left;
  }
  .min{
    width: 10%;
    left: 1%;
  }
  .max{
    width: 10%;
    left: 1%;
  }
  .rate{
    width: 10%;
    left: 1%;
  }
  .zuixiao{
    margin-left: 20%;
  }
  .zuida{
    margin-left: 20%;
  }
</style>
