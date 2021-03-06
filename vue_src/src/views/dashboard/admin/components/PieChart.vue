<template>
  <div :class="className" :style="{height:height,width:width}" />
</template>

<script>
import echarts from 'echarts'
require('echarts/theme/macarons') // echarts theme
import resize from './mixins/resize'
import { getCard } from '@/api/home'
import { Encrypt } from '@/utils/rsa'
import { getToken } from '@/utils/auth'

export default {
  mixins: [resize],
  props: {
    className: {
      type: String,
      default: 'chart'
    },
    width: {
      type: String,
      default: '100%'
    },
    height: {
      type: String,
      default: '300px'
    }
  },
  data() {
    return {
      chart: null,
      target: 0,
      scan: 0,
      port: 0,
      vulner: 0
    }
  },
  watch: {
    target: {
      handler() {
        this.initChart()
      },
      deep: true
    },
    scan: {
      handler() {
        this.initChart()
      },
      deep: true
    },
    port: {
      handler() {
        this.initChart()
      },
      deep: true
    },
    vulner: {
      handler() {
        this.initChart()
      },
      deep: true
    }
  },
  mounted() {
    this.$nextTick(() => {
      this.handleCard()
      this.initChart()
    })
  },
  beforeDestroy() {
    if (!this.chart) {
      return
    }
    this.chart.dispose()
    this.chart = null
  },
  methods: {
    handleCard() {
      let data = {
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      getCard(params).then(response => {
        this.target = response.data[0]
        this.scan = response.data[1]
        this.port = response.data[2]
        this.vulner = response.data[3]
      })
    },
    initChart() {
      this.chart = echarts.init(this.$el, 'macarons')

      this.chart.setOption({
        tooltip: {
          trigger: 'item',
          formatter: '{a} <br/>{b} : {c} ({d}%)'
        },
        legend: {
          left: 'center',
          bottom: '10',
          data: ['目标数量', '扫描次数', '端口数量', '漏洞数量']
        },
        series: [
          {
            name: 'WEEKLY WRITE ARTICLES',
            type: 'pie',
            roseType: 'radius',
            radius: [15, 95],
            center: ['50%', '38%'],
            data: [
              { value: this.target, name: '目标数量' },
              { value: this.scan, name: '扫描次数' },
              { value: this.port, name: '端口数量' },
              { value: this.vulner, name: '漏洞数量' }
            ],
            animationEasing: 'cubicInOut',
            animationDuration: 2600
          }
        ]
      })
    }
  }
}
</script>
