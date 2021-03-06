<template>
  <el-row :gutter="60" class="panel-group">
    <el-col :xs="12" :sm="12" :lg="6" class="card-panel-col">
      <div class="card-panel" @click="handleSetLineChartData('newVisitis')">
        <div class="card-panel-icon-wrapper icon-target">
          <i class="el-icon-link" style="font-size: 60px" />
        </div>
        <div class="card-panel-description">
          <div class="card-panel-text">
            目标数量
          </div>
          <count-to :start-val="0" :end-val="target" :duration="2600" class="card-panel-num" />
        </div>
      </div>
    </el-col>
    <el-col :xs="12" :sm="12" :lg="6" class="card-panel-col">
      <div class="card-panel" @click="handleSetLineChartData('messages')">
        <div class="card-panel-icon-wrapper icon-view">
          <i class="el-icon-view" style="font-size: 60px" />
        </div>
        <div class="card-panel-description">
          <div class="card-panel-text">
            扫描次数
          </div>
          <count-to :start-val="0" :end-val="scan" :duration="3000" class="card-panel-num" />
        </div>
      </div>
    </el-col>
    <el-col :xs="12" :sm="12" :lg="6" class="card-panel-col">
      <div class="card-panel" @click="handleSetLineChartData('purchases')">
        <div class="card-panel-icon-wrapper icon-port">
          <i class="el-icon-info" style="font-size: 60px" />
        </div>
        <div class="card-panel-description">
          <div class="card-panel-text">
            端口数量
          </div>
          <count-to :start-val="0" :end-val="port" :duration="3200" class="card-panel-num" />
        </div>
      </div>
    </el-col>
    <el-col :xs="12" :sm="12" :lg="6" class="card-panel-col">
      <div class="card-panel" @click="handleSetLineChartData('shoppings')">
        <div class="card-panel-icon-wrapper icon-vulner">
          <i class="el-icon-s-grid" style="font-size: 60px" />
        </div>
        <div class="card-panel-description">
          <div class="card-panel-text">
            漏洞数量
          </div>
          <count-to :start-val="0" :end-val="vulner" :duration="3600" class="card-panel-num" />
        </div>
      </div>
    </el-col>
  </el-row>
</template>

<script>
import CountTo from 'vue-count-to'
import { getCard } from '@/api/home'
import { Encrypt } from '@/utils/rsa'
import { getToken } from '@/utils/auth'

export default {
  components: {
    CountTo
  },
  data() {
    return {
      target: 0,
      scan: 0,
      port: 0,
      vulner: 0
    }
  },
  beforeCreate() {
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
  methods: {
    handleSetLineChartData(type) {
      this.$emit('handleSetLineChartData', type)
    }
  }
}
</script>

<style lang="scss" scoped>
.panel-group {
  margin-top: 18px;

  .card-panel-col {
    margin-bottom: 32px;
  }

  .card-panel {
    height: 108px;
    cursor: pointer;
    font-size: 12px;
    position: relative;
    overflow: hidden;
    color: #666;
    background: #fff;
    box-shadow: 4px 4px 40px rgba(0, 0, 0, .05);
    border-color: rgba(0, 0, 0, .05);

    &:hover {
      .card-panel-icon-wrapper {
        color: #fff;
      }
    }

    .icon-target {
      color: #7cebcf;
    }

    .icon-view {
      color: #5a8cc5;
    }

    .icon-port {
      color: #34bfa3
    }

    .icon-vulner {
      color: #12c4e4
    }

    .card-panel-icon-wrapper {
      float: left;
      margin: 14px 0 0 14px;
      padding: 16px;
      transition: all 0.38s ease-out;
      border-radius: 6px;
    }

    .card-panel-icon {
      float: left;
      font-size: 48px;
    }

    .card-panel-description {
      float: right;
      font-weight: bold;
      margin: 26px;
      margin-left: 0px;

      .card-panel-text {
        line-height: 18px;
        color: rgba(0, 0, 0, 0.45);
        font-size: 16px;
        margin-bottom: 12px;
      }

      .card-panel-num {
        font-size: 20px;
      }
    }
  }
}

@media (max-width:550px) {
  .card-panel-description {
    display: none;
  }

  .card-panel-icon-wrapper {
    float: none !important;
    width: 100%;
    height: 100%;
    margin: 0 !important;

    .svg-icon {
      display: block;
      margin: 14px auto !important;
      float: none !important;
    }
  }
}
</style>
