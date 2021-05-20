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
        框架信息: {{ targetdata.finger }}
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
          <el-badge v-show="domain_total>0" :value="domain_total" class="badge-a" />
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
        <pagination v-show="domain_total>=0" :total="domain_total" :page.sync="page.pageNum" :limit.sync="page.pageSize" @pagination="getList" />
      </el-tab-pane>
      <el-tab-pane name="path" :disabled="path_flag">
        <span slot="label">
          目录
          <el-badge v-show="path_total>0" :value="path_total" class="badge-a" />
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
        <pagination v-show="path_total>=0" :total="path_total" :page.sync="page.pageNum" :limit.sync="page.pageSize" @pagination="getList" />
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
      pos: 0,
      target: '',
      targetdata: {
        'scan_status': '',
        'scan_schedule': '',
        'vulner_number': '',
        'finger': ''
      },
      domain_total: 10,
      path_total: 10,
      page: {
        pageNum: 1,
        pageSize: 10
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
    this.getList()
    // init the default selected tab
    const tab = this.$route.query.tab
    if (tab) {
      this.activeName = tab
    }
  },
  methods: {
    showCreatedTimes() {
    },
    getList() {
      this.loading = true
      let data = {
        'target': this.target,
        'pagenum': this.page.pageNum,
        'pagesize': this.page.pageSize,
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = { 'data': Encrypt(data) }
      targetDetail(params).then(response => {
        this.targetdata.scan_status = response.data.target.result[0].scan_status
        this.targetdata.scan_schedule = response.data.target.result[0].scan_schedule
        this.targetdata.vulner_number = response.data.target.result[0].vulner_number
        this.targetdata.finger = response.data.target.result[0].finger
        this.domainlist = response.data.domain.result
        this.pathlist = response.data.path.result
        this.getSpanArr()
        this.domain_total = response.data.domain.total
        this.path_total = response.data.path.total
        this.loading = false
      })
    },
    getSpanArr(data) {
      this.domainlist.forEach(v => {
        v.rowspan = 1
      })
      // 双层循环
      for (let i = 0; i < this.domainlist.length; i++) {
        // 内层循环，上面已经给所有的行都加了v.rowspan = 1
        // 这里进行判断
        // 如果当前行的id和下一行的id相等
        // 就把当前v.rowspan + 1
        // 下一行的v.rowspan - 1
        for (let j = i + 1; j < this.domainlist.length; j++) {
          // 此处可根据相同字段进行合并，此处是根据的id
          if (this.domainlist[i].id === this.domainlist[j].id) {
            this.domainlist[i].rowspan++
            this.domainlist[j].rowspan--
          }
        }
        // 这里跳过已经重复的数据
        i = i + this.domainlist[i].rowspan - 1
      }
      this.pathlist.forEach(v => {
        v.rowspan = 1
      })
      // 双层循环
      for (let i = 0; i < this.pathlist.length; i++) {
        // 内层循环，上面已经给所有的行都加了v.rowspan = 1
        // 这里进行判断
        // 如果当前行的id和下一行的id相等
        // 就把当前v.rowspan + 1
        // 下一行的v.rowspan - 1
        for (let j = i + 1; j < this.pathlist.length; j++) {
          // 此处可根据相同字段进行合并，此处是根据的id
          if (this.pathlist[i].id === this.pathlist[j].id) {
            this.pathlist[i].rowspan++
            this.pathlist[j].rowspan--
          }
        }
        // 这里跳过已经重复的数据
        i = i + this.pathlist[i].rowspan - 1
      }
    },
    objectSpanMethod({ row, column, rowIndex, columnIndex }) {
      if (columnIndex === 0) {
        return {
          rowspan: row.rowspan,
          colspan: 1
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
