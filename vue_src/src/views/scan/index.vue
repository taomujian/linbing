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
      <el-table-column label="ID" sortable align="center" prop="id" width="100">
        <template slot-scope="{row}">
          <span>{{ row.id }}</span>
        </template>
      </el-table-column>
      <el-table-column label="目标" sortable prop="target" align="center" width="200">
        <template slot-scope="{row}">
          <span class="link-type" @click="handleDetail(row)">{{ row.target }}</span>
        </template>
      </el-table-column>
      <el-table-column label="目标IP" sortable prop="target_ip" align="center">
        <template slot-scope="{row}">
          <span>{{ row.target_ip }}</span>
        </template>
      </el-table-column>
      <el-table-column label="扫描时间" sortable prop="scan_time" align="center">
        <template slot-scope="{row}">
          <span>{{ row.scan_time | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
        </template>
      </el-table-column>
      <el-table-column label="扫描状态" sortable prop="scan_status" class-name="status-col">
        <template slot-scope="{row}">
          <el-tag effect="dark" :type="row.scan_status | statusFilter">
            {{ row.scan_status }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="扫描进度" sortable prop="scan_schedule" align="center">
        <template slot-scope="{row}">
          <el-tag effect="dark" :type="row.scan_schedule | statusFilter">
            {{ row.scan_schedule }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column label="漏洞数量" sortable prop="vulner_number" align="center">
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
      list: [],
      total: 0,
      listLoading: true,
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
    this.websocketclose()
    this.initWebSocket()
    this.getList()
  },
  destroyed() {
    this.websocketclose()
  },
  // 销毁定时器
  methods: {
    getList() {
      this.listLoading = true
      let data = {
        'pagenum': this.page.pageNum,
        'pagesize': this.page.pageSize,
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
      const { protocol, host } = location
      this.websocket = new WebSocket(`${protocol === 'https' ? 'wss' : 'ws'}://${host}/ws/scan/status`)
      this.websocket.onmessage = this.websocketonmessage
      // 连接建立时触发
      this.websocket.onopen = this.websocketonopen
      // 通信发生错误时触发
      this.websocket.onerror = this.websocketonerror
      // 连接关闭时触发
      this.websocket.onclose = this.websocketclose
    },
    // 连接建立时触发
    websocketonopen() {
      // 连接建立之后执行send方法发送数据
      let data = {
        'pagenum': this.page.pageNum,
        'pagesize': this.page.pageSize,
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
    },
    // 客户端接收服务端数据时触发
    websocketonmessage(response) {
      var data = JSON.parse(response.data)
      // 收到变化的数据重新更新数据
      if (data.data !== '' && JSON.stringify(data.data.result) !== JSON.stringify(this.list)) {
        this.listLoading = true
        this.list = data.data.result
        if (data.data === '') {
          this.list = []
          this.page.total = 0
        } else {
          this.page.total = data.data.total
        }
        setTimeout(() => {
          this.listLoading = false
        }, 0.5 * 1000)
      }
    },
    websocketsend(Data) {
      // 数据发送
      if (this.websocket.readyState === 1) {
        this.websocket.send(Data)
      }
    },
    // 连接关闭时触发
    websocketclose() {
      // 关闭
      if (this.websocket) {
        this.websocket.close()
      }
    }
  }
}
</script>
