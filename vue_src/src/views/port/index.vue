<style lang="scss" scoped>
  @import '@/styles/port.scss';
</style>

<template>
  <div class="app-container">
    <div class="filter-container">
      <el-input v-model="listQuery.target" placeholder="目标关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-input v-model="listQuery.scan_ip" placeholder="IP关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-input v-model="listQuery.port" placeholder="端口关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-input v-model="listQuery.finger" placeholder="Web框架关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-input v-model="listQuery.product" placeholder="端口产品关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-input v-model="listQuery.title" placeholder="标题关键字" class="header" @keyup.enter.native="handleFilter" />
      <el-button v-waves class="button" type="primary" icon="el-icon-search" @click="handleFilter">
        搜索
      </el-button>
      <el-button :loading="downloadLoading" class="button" type="primary" icon="el-icon-document" @click="handleDownload">下载</el-button>
    </div>

    <el-table
      :key="tableKey"
      v-loading="listLoading"
      :data="list"
      border
      fit
      highlight-current-row
      style="width: 100%;"
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
      <el-table-column label="IP" sortable prop="scan_ip" align="center" width="120">
        <template slot-scope="{row}">
          <span>{{ row.scan_ip }}</span>
        </template>
      </el-table-column>
      <el-table-column label="PORT" sortable prop="port" align="center" width="100">
        <template slot-scope="{row}">
          <div v-if="row.protocol == 'https'">
            <span class="link-type">
              <a :href="'https://'+row.scan_ip+':'+row.port" target="_blank" class="buttonText">{{ row.port }}</a>
            </span>
          </div>
          <div v-else-if="row.protocol == 'http'">
            <span class="link-type">
              <a :href="'http://'+row.scan_ip+':'+row.port" target="_blank" class="buttonText">{{ row.port }}</a>
            </span>
          </div>
          <div v-else>
            <span>{{ row.port }}</span>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="Web框架" sortable prop="finger" align="center" width="110">
        <template slot-scope="{row}">
          <span>{{ row.finger }}</span>
        </template>
      </el-table-column>
      <el-table-column label="协议" sortable prop="protocol" align="center">
        <template slot-scope="{row}">
          <span>{{ row.protocol }}</span>
        </template>
      </el-table-column>
      <el-table-column label="产品" sortable prop="product" align="center" width="120">
        <template slot-scope="{row}">
          <span>{{ row.product }}</span>
        </template>
      </el-table-column>
      <el-table-column label="版本" sortable prop="version" align="center" width="80">
        <template slot-scope="{row}">
          <span>{{ row.version }}</span>
        </template>
      </el-table-column>
      <el-table-column label="标题" sortable prop="title" align="center" width="100">
        <template slot-scope="{row}">
          <span>{{ row.title }}</span>
        </template>
      </el-table-column>
      <el-table-column label="横幅" sortable prop="banner" align="center" width="140">
        <template slot-scope="{row}">
          <span>{{ row.banner }}</span>
        </template>
      </el-table-column>
      <el-table-column label="扫描时间" sortable prop="scan_time" width="120px" align="center">
        <template slot-scope="{row}">
          <span>{{ row.scan_time | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" align="center" class-name="small-padding fixed-width">
        <template slot-scope="{row}">
          <el-button size="mini" type="danger" icon="el-icon-error" @click="handleDelete(row)">
            删除
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <pagination v-show="page.total>=0" :total="page.total" :page.sync="page.pageNum" :limit.sync="page.pageSize" @pagination="getList" />
  </div>
</template>

<script>
import { portList, portDownload, deletePort } from '@/api/port'
import { Encrypt } from '@/utils/rsa'
import { getToken } from '@/utils/auth'
import waves from '@/directive/waves' // waves directive
import Pagination from '@/components/Pagination' // secondary package based on el-pagination

export default {
  name: 'AssetManager',
  components: { Pagination },
  directives: { waves },
  data() {
    return {
      tableKey: 0,
      list: null,
      allList: null,
      total: 0,
      listLoading: true,
      page: {
        pageNum: 1,
        pageSize: 10,
        total: 10
      },
      downloadLoading: false,
      listQuery: {
        target: '',
        scan_ip: '',
        port: '',
        finger: '',
        product: '',
        title: ''
      }
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
        'token': getToken(),
        'listQuery': JSON.stringify(this.listQuery)
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      portList(params).then(response => {
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
    formatJson(filterVal, jsonData) {
      return jsonData.map(v => filterVal.map(j => {
        return v[j]
      }))
    },
    dateFormat(fmt, date) {
      let ret
      const opt = {
        'Y+': date.getFullYear().toString(), // 年
        'm+': (date.getMonth() + 1).toString(), // 月
        'd+': date.getDate().toString(), // 日
        'H+': date.getHours().toString(), // 时
        'M+': date.getMinutes().toString(), // 分
        'S+': date.getSeconds().toString() // 秒
        // 有其他格式化字符需求可以继续添加，必须转化成字符串
      }
      for (const k in opt) {
        ret = new RegExp('(' + k + ')').exec(fmt)
        if (ret) {
          fmt = fmt.replace(
            ret[1],
            ret[1].length === 1 ? opt[k] : opt[k].padStart(ret[1].length, '0')
          )
        }
      }
      return fmt
    },
    handleDownload() {
      let data = {
        'token': getToken(),
        'listQuery': JSON.stringify(this.listQuery)
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      portDownload(params).then(response => {
        if (response.data === '') {
          this.allList = []
          this.$notify({
            message: '数据为空,无法下载!',
            type: 'warning',
            center: true,
            duration: 2 * 1000
          })
        } else {
          this.allList = response.data.result
          this.downloadLoading = true
          import('@/vendor/Export2Excel').then(excel => {
            const tHeader = ['ID', '目标', 'IP', '端口', 'IP_PORT', 'Web框架', '协议', '产品', '版本', '标题', '横幅']
            const filterVal = ['id', 'target', 'scan_ip', 'port', 'ip_port', 'finger', 'protocol', 'product', 'version', 'title', 'banner']
            const data = this.formatJson(filterVal, this.allList)
            const fileName = this.dateFormat('YYYYmmddHHMMSS', new Date())
            excel.export_json_to_excel({
              header: tHeader,
              data,
              filename: fileName,
              autoWidth: this.autoWidth,
              bookType: this.bookType
            })
            this.downloadLoading = false
          })
          this.$notify({
            message: '下载成功!',
            type: 'success',
            center: true,
            duration: 3 * 1000
          })
        }
      })
    },
    handleDelete(row) {
      let data = {
        'target': row.target,
        'scan_ip': row.scan_ip,
        'port': row.port,
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      deletePort(params).then(() => {
        this.getList()
        this.$notify({
          message: '端口删除成功!',
          type: 'success',
          center: true,
          duration: 3 * 1000
        })
      })
    }
  }
}
</script>
