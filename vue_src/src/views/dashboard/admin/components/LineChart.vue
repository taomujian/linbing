<template>
  <div :class="className" :style="{height:height,width:width}" />
</template>

<script>
import echarts from 'echarts'
require('echarts/theme/macarons') // echarts theme
import resize from './mixins/resize'
import { get7day } from '@/api/home'
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
      default: '350px'
    },
    autoResize: {
      type: Boolean,
      default: true
    }
  },
  data() {
    return {
      chart: null,
      datanums: [],
      target: [],
      scan: [],
      port: [],
      vulner: []
    }
  },
  watch: {
    target: {
      deep: true,
      handler() {
        this.setOptions()
      }
    },
    scan: {
      deep: true,
      handler() {
        this.setOptions()
      }
    },
    port: {
      deep: true,
      handler() {
        this.setOptions()
      }
    },
    vulner: {
      deep: true,
      handler() {
        this.setOptions()
      }
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
    getDay(day) {
      const today = new Date()
      const targetday_milliseconds = today.getTime() + 1000 * 60 * 60 * 24 * (day + 1)
      today.setTime(targetday_milliseconds) // 注意，这行是关键代码
      const tYear = today.getFullYear()
      let tMonth = today.getMonth()
      let tDate = today.getDate()
      tMonth = this.doHandleMonth(tMonth + 1)
      tDate = this.doHandleMonth(tDate)
      return tYear + '-' + tMonth + '-' + tDate
    },
    doHandleMonth(month) {
      let m = month
      if (month.toString().length === 1) {
        m = '0' + month
      }
      return m
    },
    handleCard() {
      let data = {
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      get7day(params).then(response => {
        this.target = response.data.target
        this.scan = response.data.scan
        this.port = response.data.port
        this.vulner = response.data.vulner
      })
    },
    initChart() {
      this.chart = echarts.init(this.$el, 'macarons')
      for (let i = 7; i > 0; i--) {
        this.datanums.push(this.getDay(-i))
      }
      this.setOptions()
    },
    setOptions() {
      this.chart.setOption({
        xAxis: {
          data: this.datanums,
          boundaryGap: false,
          axisTick: {
            show: false
          }
        },
        grid: {
          left: 10,
          right: 10,
          bottom: 20,
          top: 30,
          containLabel: true
        },
        tooltip: {
          trigger: 'axis',
          axisPointer: {
            type: 'cross'
          },
          padding: [5, 10]
        },
        yAxis: {
          axisTick: {
            show: false
          }
        },
        legend: {
          data: ['目标数量', '扫描次数', '端口数量', '漏洞数量']
        },
        series: [{
          name: '目标数量', itemStyle: {
            normal: {
              color: '#7cebcf',
              lineStyle: {
                color: '#7cebcf',
                width: 2
              },
              areaStyle: {
                color: '#7cebcf'
              }
            }
          },
          smooth: true,
          type: 'line',
          data: this.target,
          animationDuration: 2800,
          animationEasing: 'cubicInOut'
        },
        {
          name: '扫描次数',
          smooth: true,
          type: 'line',
          itemStyle: {
            normal: {
              color: '#5a8cc5',
              lineStyle: {
                color: '#5a8cc5',
                width: 2
              },
              areaStyle: {
                color: '#5a8cc5'
              }
            }
          },
          data: this.scan,
          animationDuration: 2800,
          animationEasing: 'quadraticOut'
        },
        {
          name: '端口数量', itemStyle: {
            normal: {
              color: '#34bfa3',
              lineStyle: {
                color: '#34bfa3',
                width: 2
              },
              areaStyle: {
                color: '#34bfa3'
              }
            }
          },
          smooth: true,
          type: 'line',
          data: this.port,
          animationDuration: 2800,
          animationEasing: 'cubicInOut'
        },
        {
          name: '漏洞数量',
          smooth: true,
          type: 'line',
          itemStyle: {
            normal: {
              color: '#12c4e4',
              lineStyle: {
                color: '#12c4e4',
                width: 2
              },
              areaStyle: {
                color: '#12c4e4'
              }
            }
          },
          data: this.vulner,
          animationDuration: 2800,
          animationEasing: 'quadraticOut'
        }]
      })
    }
  }
}
</script>
