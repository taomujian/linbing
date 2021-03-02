<style lang="scss" scoped>
  @import '@/styles/scan.scss';
</style>

<template>
  <div class="app-container">
    <div class="filter-container">
      <el-input v-model="listQuery.target" placeholder="目标关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-input v-model="listQuery.description" placeholder="描述关键字" class="header" @keyup.enter.native="handleFilter" />
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
      <el-table-column label="目标" sortable align="center">
        <template slot-scope="{row}">
          <span>{{ row.target }}</span>
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
    </el-table>
    <pagination v-show="page.total>=0" :total="page.total" :page.sync="page.pageNum" :limit.sync="page.pageSize" @pagination="getList" />
  </div>
</template>

<script>
import { scanList } from '@/api/scan'
import { Encrypt } from '@/utils/rsa'
import { getToken } from '@/utils/auth'
import waves from '@/directive/waves' // waves directive
import Pagination from '@/components/Pagination' // secondary package based on el-pagination

export default {
  name: 'ScanList',
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
      page: {
        pageNum: 1,
        pageSize: 10,
        total: 10
      },
      listQuery: {
        target: '',
        description: '',
        scan_status: '',
        scan_schedule: ''
      },
      statusOptions: ['全部', '未开始', '扫描中', '扫描结束', '扫描失败'],
      scheduleOptions: ['全部', '未开始', '子域名扫描中', '端口扫描中', '目录扫描中', 'POC扫描中', '扫描结束', '扫描失败']
    }
  },
  created() {
    this.getList()
  },
  methods: {
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
    handleFilter() {
      this.page.pageNum = 1
      this.getList()
    }
  }
}
</script>
