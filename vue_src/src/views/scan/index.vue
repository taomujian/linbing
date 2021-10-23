<style lang="scss" scoped>
  @import '@/styles/scan.scss';
</style>

<template>
  <div class="app-container">
    <div class="filter-container">
      <el-input v-model="listQuery.target" placeholder="目标关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-select v-model="listQuery.scan_status" placeholder="扫描状态" clearable class="header">
        <el-option v-for="item in statusOptions" :key="item" :label="item" :value="item" />
      </el-select>
      <el-select v-model="listQuery.scan_schedule" placeholder="扫描进度" clearable class="header">
        <el-option v-for="item in scheduleOptions" :key="item" :label="item" :value="item" />
      </el-select>
      <el-button v-waves class="button" type="primary" icon="el-icon-search" @click="handleFilter">
        搜索
      </el-button>
    </div>
    <el-table
      :key="tableKey"
      v-loading="listLoading"
      :data="list"
      border
      fit
      highlight-current-row
      style="width: 100%; overflow: hidden;"
    >
      <el-table-column label="ID" sortable align="center" width="100">
        <template slot-scope="{row}">
          <span>{{ row.id }}</span>
        </template>
      </el-table-column>
      <el-table-column label="目标" sortable align="center" width="200">
        <template slot-scope="{row}">
          <div v-if="isurl(row.target) === true">
            <span class="link-type" @click="handleDetail(row)">{{ row.target }}</span>
          </div>
          <div v-else>
            <span>{{ row.target }}</span>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="目标IP" sortable align="center">
        <template slot-scope="{row}">
          <span>{{ row.target_ip }}</span>
        </template>
      </el-table-column>
      <el-table-column label="扫描时间" sortable align="center">
        <template slot-scope="{row}">
          <span>{{ row.scan_time | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
        </template>
      </el-table-column>
      <el-table-column label="扫描状态" sortable class-name="status-col">
        <template slot-scope="{row}">
          <el-tag effect="dark" :type="row.scan_status | statusFilter">
            {{ row.scan_status }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="扫描进度" sortable align="center">
        <template slot-scope="{row}">
          <el-tag effect="dark" :type="row.scan_schedule | statusFilter">
            {{ row.scan_schedule }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="漏洞数量" sortable align="center">
        <template slot-scope="{row}">
          <span>{{ row.vulner_number }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" align="center" width="340" class-name="small-padding fixed-width">
        <template slot-scope="{row}">
          <el-button type="primary" size="mini" icon="el-icon-video-play" @click="handlePause(row)">
            暂停扫描
          </el-button>
          <el-button type="primary" size="mini" icon="el-icon-edit" @click="handleResume(row)">
            恢复扫描
          </el-button>
          <el-button size="mini" type="danger" icon="el-icon-error" @click="handleCancel(row)">
            取消扫描
          </el-button>
        </template>
      </el-table-column>
    </el-table>
    <pagination v-show="page.total>=0" :total="page.total" :page.sync="page.pageNum" :limit.sync="page.pageSize" @pagination="getList" />
  </div>
</template>

<script>
import { scanList, pauseScan, resumeScan, cancelScan } from '@/api/scan'
import { Encrypt } from '@/utils/rsa'
import { getToken } from '@/utils/auth'
import waves from '@/directive/waves' // waves directive
import Pagination from '@/components/Pagination' // secondary package based on el-pagination

export default {
  name: 'ScanManager',
  components: { Pagination },
  directives: { waves },
  filters: {
    statusFilter(status) {
      const statusMap = {
        未开始: 'info',
        扫描结束: 'success',
        扫描中: '',
        子域名扫描中: '',
        端口扫描中: '',
        目录扫描中: '',
        POC扫描中: '',
        扫描失败: 'danger'
      }
      return statusMap[status]
    }
  },
  data() {
    return {
      tableKey: 0,
      list: null,
      total: 0,
      listLoading: true,
      lockReconnect: false, // 是否真正建立连接
      timeout: 30000, // 58秒一次心跳
      timeoutObj: null, // 心跳心跳倒计时
      serverTimeoutObj: null, // 心跳倒计时
      timeoutnum: null, // 断开重连倒计时
      page: {
        pageNum: 1,
        pageSize: 10,
        total: 10
      },
      listQuery: {
        target: '',
        scan_status: '',
        scan_schedule: ''
      },
      statusOptions: ['全部', '未开始', '扫描中', '扫描结束', '扫描失败'],
      scheduleOptions: ['全部', '未开始', '子域名扫描中', '端口扫描中', '目录扫描中', 'POC扫描中', '扫描结束', '扫描失败']
    }
  },
  created() {
    this.getList()
    this.initWebSocket()
  },

  destroyed() {
    this.websock.close() // 离开路由之后断开websocket连接
  },
  mounted() {
    this.getList()
  },
  // 销毁定时器
  methods: {
    isurl(value) {
      const ip_reg = /^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/
      const domain_reg = /^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$/
      if (value.startsWith('http://') === true) {
        return true
      } else if (value.startsWith('https://') === true) {
        return true
      } else if (ip_reg.test(value)) {
        return false
      } else if (domain_reg.test(value)) {
        return true
      }
      return false
    },
    getList() {
      this.listLoading = true
      let data = {
        'pagenum': this.page.pageNum,
        'pagesize': this.page.pageSize,
        'flag': '0',
        'token': getToken(),
        'listQuery': JSON.stringify(this.listQuery)
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      scanList(params).then(response => {
        if (response.data === '') {
          this.list = []
          this.page.total = 0
        } else {
          this.list = response.data.result
          this.page.total = response.data.total
        }
        setTimeout(() => {
          this.listLoading = false
        }, 0.5 * 1000)
      })
    },
    handlePause(row) {
      let data = {
        'scan_id': row.scan_id,
        'target': row.target,
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      pauseScan(params).then(response => {
        if (response.data === '请求正常') {
          this.$notify({
            message: '暂停扫描成功!',
            type: 'success',
            center: true,
            duration: 3 * 1000
          })
        } else {
          this.$notify({
            message: '目标不处于扫描状态,无法暂停扫描!',
            type: 'error',
            center: true,
            duration: 3 * 1000
          })
        }
      })
    },
    handleResume(row) {
      let data = {
        'scan_id': row.scan_id,
        'target': row.target,
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      resumeScan(params).then(response => {
        if (response.data === '请求正常') {
          this.$notify({
            message: '恢复扫描成功!',
            type: 'success',
            center: true,
            duration: 3 * 1000
          })
        } else {
          this.$notify({
            message: '目标不处于暂停扫描状态,无法恢复扫描!',
            type: 'error',
            center: true,
            duration: 3 * 1000
          })
        }
      })
    },
    handleCancel(row) {
      let data = {
        'scan_id': row.scan_id,
        'target': row.target,
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      cancelScan(params).then(response => {
        if (response.data === '请求正常') {
          this.$notify({
            message: '取消扫描成功!',
            type: 'success',
            center: true,
            duration: 3 * 1000
          })
        } else {
          this.$notify({
            message: '扫描已结束,无法取消扫描!',
            type: 'error',
            center: true,
            duration: 3 * 1000
          })
        }
      })
    },
    handleDetail(row) {
      this.$router.push({
        name: 'TargetDetail',
        query: {
          params: row['target']
        }
      })
    },
    handleFilter() {
      this.page.pageNum = 1
      this.getList()
    },
    initWebSocket() {
      // 初始化weosocket
      const wsuri = 'ws://' + process.env.VUE_APP_BASE_API.replace('http://', '') + '/ws/scan/status'
      this.websock = new WebSocket(wsuri)
      // 客户端接收服务端数据时触发
      this.websock.onmessage = this.websocketonmessage
      // 连接建立时触发
      this.websock.onopen = this.websocketonopen
      // 通信发生错误时触发
      this.websock.onerror = this.websocketonerror
      // 连接关闭时触发
      this.websock.onclose = this.websocketclose
    },
    // 连接建立时触发
    websocketonopen() {
      // 开启心跳
      this.start()
      // 连接建立之后执行send方法发送数据
      let data = {
        'pagenum': this.page.pageNum,
        'pagesize': this.page.pageSize,
        'flag': '0',
        'token': getToken(),
        'listQuery': JSON.stringify(this.listQuery)
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      this.websocketsend(JSON.stringify(params))
    },
    // 通信发生错误时触发
    websocketonerror() {
      console.log('出现错误')
      this.reconnect()
    },
    // 客户端接收服务端数据时触发
    websocketonmessage(response) {
      var data = JSON.parse(response.data)
      // 收到变化的数据重新更新数据
      if (data.data.result !== this.list) {
        this.listLoading = true
        this.list = data.data.result
        if (data.data === '') {
          this.list = []
          this.page.total = 0
        } else {
          this.list = data.data.result
          this.page.total = data.data.total
        }
        setTimeout(() => {
          this.listLoading = false
        }, 0.5 * 1000)
      }
      // 收到服务器信息，心跳重置
      this.reset()
    },
    websocketsend(Data) {
      // 数据发送
      this.websock.send(Data)
    },
    // 连接关闭时触发
    websocketclose(e) {
      // 关闭
      this.reconnect()
    },
    reconnect() {
      // 重新连接
      var that = this
      if (that.lockReconnect) {
        return
      }
      that.lockReconnect = true
      // 没连接上会一直重连，设置延迟避免请求过多
      that.timeoutnum && clearTimeout(that.timeoutnum)
      that.timeoutnum = setTimeout(function() {
        // 新连接
        that.initWebSocket()
        that.lockReconnect = false
      }, 5000)
    },
    reset() {
      // 重置心跳
      var that = this
      // 清除时间
      clearTimeout(that.timeoutObj)
      clearTimeout(that.serverTimeoutObj)
      // 重启心跳
      that.start()
    },
    start() {
      // 开启心跳
      // console.log('开启心跳')
      var self = this
      self.timeoutObj && clearTimeout(self.timeoutObj)
      self.serverTimeoutObj && clearTimeout(self.serverTimeoutObj)
      self.timeoutObj = setTimeout(function() {
        // 这里发送一个心跳，后端收到后，返回一个心跳消息，
        if (self.websock.readyState === 1) {
          // 如果连接正常
          // self.websock.send("heartCheck"); //这里可以自己跟后端约定
        } else {
          // 否则重连
          self.reconnect()
        }
        self.serverTimeoutObj = setTimeout(function() {
          // 超时关闭
          self.websock.close()
        }, self.timeout)
      }, self.timeout)
    }
  }
}
</script>
