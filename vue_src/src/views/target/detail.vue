<style lang="scss" scoped>
  @import '@/styles/detail.scss';
</style>

<template>
  <div class="tab-container">
    <el-card class="box-card">
      <div slot="header" class="title">
        <span>目标:{{ target }}</span>
      </div>
      <div class="p">
        扫描状态: {{ targetdata.scan_status }}
      </div>
      <div class="p">
        扫描进度: {{ targetdata.scan_schedule }}
      </div>
      <div class="p">
        漏洞数量: {{ targetdata.vulner_number }}
      </div>
    </el-card>
    <el-tabs v-model="activeName" type="card" class="tab">
      <el-tab-pane label="子域名" name="domain">
        <span slot="label">
          子域名
          <el-badge v-show="domainpage.total>0" :value="domainpage.total" class="badge-a" />
        </span>
        <el-table :data="domainlist" :span-method="objectSpanMethod" border fit highlight-current-row style="width: 100%">
          <el-table-column
            v-loading="loading"
            align="center"
            label="扫描ID"
            sortable
            width="100"
            element-loading-text="请给我点时间！"
          >
            <template slot-scope="{row}">
              <span>{{ row.scan_id }}</span>
            </template>
          </el-table-column>

          <el-table-column align="center" sortable label="扫描时间">
            <template slot-scope="{row}">
              <span>{{ row.scan_time | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
            </template>
          </el-table-column>

          <el-table-column align="center" sortable label="子域名">
            <template slot-scope="{row}">
              <span>{{ row.domain }}</span>
            </template>
          </el-table-column>

          <el-table-column align="center" sortable label="子域名IP">
            <template slot-scope="{row}">
              <span>{{ row.domain_ip }}</span>
            </template>
          </el-table-column>
        </el-table>
        <pagination v-show="domainpage.total>=0" :total="domainpage.total" :page.sync="domainpage.pageNum" :limit.sync="domainpage.pageSize" @pagination="getDomainList" />
      </el-tab-pane>
      <el-tab-pane name="path" :disabled="path_flag">
        <span slot="label">
          目录
          <el-badge v-show="pathpage.total>0" :value="pathpage.total" class="badge-a" />
        </span>
        <el-table :data="pathlist" :span-method="objectSpanMethod" border fit highlight-current-row style="width: 100%">
          <el-table-column
            v-loading="loading"
            align="center"
            label="扫描ID"
            sortable
            width="100"
            element-loading-text="请给我点时间！"
          >
            <template slot-scope="{row}">
              <span>{{ row.scan_id }}</span>
            </template>
          </el-table-column>

          <el-table-column align="center" sortable label="扫描时间">
            <template slot-scope="{row}">
              <span>{{ row.scan_time | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
            </template>
          </el-table-column>

          <el-table-column align="center" sortable label="路径">
            <template slot-scope="{row}">
              <span class="link-type">
                <a :href="target+'/'+row.path" target="_blank" class="buttonText">{{ row.path }}</a>
              </span>
            </template>
          </el-table-column>

          <el-table-column align="center" sortable label="状态码">
            <template slot-scope="{row}">
              <span>{{ row.status_code }}</span>
            </template>
          </el-table-column>
        </el-table>
        <pagination v-show="pathpage.total>=0" :total="pathpage.total" :page.sync="pathpage.pageNum" :limit.sync="pathpage.pageSize" @pagination="getPathList" />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script>
import { Encrypt } from '@/utils/rsa'
import { getToken } from '@/utils/auth'
import { targetDetail } from '@/api/target'
import Pagination from '@/components/Pagination' // secondary package based on el-pagination

export default {
  name: 'TargetDetail',
  components: { Pagination },
  data() {
    return {
      activeName: 'domain',
      domainlist: null,
      pathlist: null,
      spanArr: [],
      target: '',
      targetdata: {
        'scan_status': '',
        'scan_schedule': '',
        'vulner_number': ''
      },
      domainpage: {
        pageNum: 1,
        pageSize: 10,
        total: 10
      },
      pathpage: {
        pageNum: 1,
        pageSize: 10,
        total: 10
      },
      path_flag: false,
      loading: false
    }
  },
  watch: {
    activeName(val) {
      this.$router.push(`${this.$route.path}?params=${this.$route.query.params}`)
    }
  },
  created() {
    this.target = this.$route.query.params
    const reg = /^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$/
    if (reg.test(this.target)) {
      this.path_flag = true
    }
    this.getDomainList()
    this.getPathList()
    // init the default selected tab
    const tab = this.$route.query.tab
    if (tab) {
      this.activeName = tab
    }
  },
  methods: {
    showCreatedTimes() {
    },
    getDomainList() {
      this.loading = true
      let data = {
        'target': this.target,
        'pagenum': this.domainpage.pageNum,
        'pagesize': this.domainpage.pageSize,
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      targetDetail(params).then(response => {
        this.targetdata.scan_status = response.data.target.result[0].scan_status
        this.targetdata.scan_schedule = response.data.target.result[0].scan_schedule
        this.targetdata.vulner_number = response.data.target.result[0].vulner_number
        this.domainlist = response.data.domain.result
        this.getSpanArr(this.domainlist)
        this.domainpage.total = response.data.domain.total
        this.loading = false
      })
    },
    getPathList() {
      this.loading = true
      let data = {
        'target': this.target,
        'pagenum': this.pathpage.pageNum,
        'pagesize': this.pathpage.pageSize,
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      targetDetail(params).then(response => {
        this.targetdata.scan_status = response.data.target.result[0].scan_status
        this.targetdata.scan_schedule = response.data.target.result[0].scan_schedule
        this.targetdata.vulner_number = response.data.target.result[0].vulner_number
        this.pathlist = response.data.path.result
        this.getSpanArr(this.pathlist)
        this.pathpage.total = response.data.path.total
        this.loading = false
      })
    },
    getSpanArr(data) {
      for (var i = 0; i < data.length; i++) {
        if (i === 0) {
          this.spanArr.push(1)
          this.pos = 0
        } else {
          // 判断当前元素与上一个元素是否相同
          if (data[i].id === data[i - 1].id) {
            this.spanArr[this.pos] += 1
            this.spanArr.push(0)
          } else {
            this.spanArr.push(1)
            this.pos = i
          }
        }
      }
    },
    objectSpanMethod({ row, column, rowIndex, columnIndex }) {
      if (columnIndex === 0) {
        const _row = this.spanArr[rowIndex]
        const _col = _row > 0 ? 1 : 0
        console.log(`rowspan:${_row} colspan:${_col}`)
        return { // [0,0] 表示这一行不显示， [2,1]表示行的合并数
          rowspan: _row,
          colspan: _col
        }
      }
    }
  }
}
</script>

<style scoped>
  .tab-container {
    margin: 30px;
  }
</style>
