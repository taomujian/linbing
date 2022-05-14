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
          <el-badge v-show="domain_label_total>0" :value="domain_label_total" class="badge-a" />
        </span>
        <el-table :data="domainlist" :span-method="objectSpanMethod" border fit highlight-current-row style="width: 100%" @sort-change="domainSortChange">
          <el-table-column
            v-loading="loading"
            align="center"
            label="扫描ID"
            prop="scan_id"
            sortable="custom"
            :sort-orders="['ascending','descending']"
            width="100"
            element-loading-text="请给我点时间！"
          >
            <template slot-scope="{row}">
              <span>{{ row.scan_id }}</span>
            </template>
          </el-table-column>

          <el-table-column align="center" label="扫描时间">
            <template slot-scope="{row}">
              <span>{{ row.scan_time | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
            </template>
          </el-table-column>

          <el-table-column align="center" prop="domain" label="子域名">
            <template slot-scope="{row}">
              <span>{{ row.domain }}</span>
            </template>
          </el-table-column>

          <el-table-column align="center" label="子域名IP">
            <template slot-scope="{row}">
              <span>{{ row.domain_ip }}</span>
            </template>
          </el-table-column>
        </el-table>
        <pagination v-show="domain_total>=0" :total="domain_total" :page.sync="page.pageNum" :limit.sync="page.pageSize" @pagination="getList" />
      </el-tab-pane>
      <el-tab-pane label="端口" name="port">
        <span slot="label">
          端口
          <el-badge v-show="port_label_total>0" :value="port_label_total" class="badge-a" />
        </span>
        <el-table :data="portlist" :span-method="objectSpanMethod" border fit highlight-current-row style="width: 100%" @sort-change="portSortChange">
          <el-table-column
            v-loading="loading"
            align="center"
            label="扫描ID"
            prop="scan_id"
            sortable="custom"
            :sort-orders="['ascending','descending']"
            width="100"
            element-loading-text="请给我点时间！"
          >
            <template slot-scope="{row}">
              <span>{{ row.scan_id }}</span>
            </template>
          </el-table-column>

          <el-table-column align="center" prop="scan_time" label="扫描时间" width="110">
            <template slot-scope="{row}">
              <span>{{ row.scan_time | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
            </template>
          </el-table-column>

          <el-table-column label="IP" prop="scan_ip" align="center" width="120">
            <template slot-scope="{row}">
              <span>{{ row.scan_ip }}</span>
            </template>
          </el-table-column>
          <el-table-column label="PORT" prop="port" align="center" width="100">
            <template slot-scope="{row}">
              <div v-if="row.protocol == 'https'">
                <span class="link-type">
                  <a :href="'https://'+row.scan_ip+':'+row.port" target="_blank" class="buttonText">{{ row.port }}</a>
                </span>
              </div>
              <div v-else-if="row.protocol == 'http'">
                <span class="link-type">
                  <a :href="'https://'+row.scan_ip+':'+row.port" target="_blank" class="buttonText">{{ row.port }}</a>
                </span>
              </div>
              <div v-else>
                <span>{{ row.port }}</span>
              </div>
            </template>
          </el-table-column>
          <el-table-column label="Web框架" prop="finger" align="center" width="110">
            <template slot-scope="{row}">
              <span>{{ row.finger }}</span>
            </template>
          </el-table-column>
          <el-table-column label="协议" prop="protocol" align="center">
            <template slot-scope="{row}">
              <span>{{ row.protocol }}</span>
            </template>
          </el-table-column>
          <el-table-column label="产品" prop="product" align="center" width="120">
            <template slot-scope="{row}">
              <span>{{ row.product }}</span>
            </template>
          </el-table-column>
          <el-table-column label="版本" prop="version" align="center" width="80">
            <template slot-scope="{row}">
              <span>{{ row.version }}</span>
            </template>
          </el-table-column>
          <el-table-column label="标题" prop="title" align="center" width="100">
            <template slot-scope="{row}">
              <span>{{ row.title }}</span>
            </template>
          </el-table-column>
          <el-table-column label="横幅" prop="banner" align="center" width="140">
            <template slot-scope="{row}">
              <span>{{ row.banner }}</span>
            </template>
          </el-table-column>
          <el-table-column label="扫描时间" prop="scan_time" width="120px" align="center">
            <template slot-scope="{row}">
              <span>{{ row.scan_time | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
            </template>
          </el-table-column>
        </el-table>
        <pagination v-show="path_total>=0" :total="port_total" :page.sync="page.pageNum" :limit.sync="page.pageSize" @pagination="getList" />
      </el-tab-pane>
      <el-tab-pane label="目录" name="path" :disabled="path_flag">
        <span slot="label">
          目录
          <el-badge v-show="path_label_total>0" :value="path_label_total" class="badge-a" />
        </span>
        <el-table :data="pathlist" :span-method="objectSpanMethod" border fit highlight-current-row style="width: 100%" @sort-change="pathSortChange">
          <el-table-column
            v-loading="loading"
            align="center"
            label="扫描ID"
            prop="scan_id"
            sortable="custom"
            :sort-orders="['ascending','descending']"
            width="100"
            element-loading-text="请给我点时间！"
          >
            <template slot-scope="{row}">
              <span>{{ row.scan_id }}</span>
            </template>
          </el-table-column>

          <el-table-column align="center" label="扫描时间">
            <template slot-scope="{row}">
              <span>{{ row.scan_time | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
            </template>
          </el-table-column>

          <el-table-column align="center" label="路径">
            <template slot-scope="{row}">
              <span class="link-type">
                <a :href="target+'/'+row.path" target="_blank" class="buttonText">{{ row.path }}</a>
              </span>
            </template>
          </el-table-column>

          <el-table-column align="center" label="状态码">
            <template slot-scope="{row}">
              <span>{{ row.status_code }}</span>
            </template>
          </el-table-column>
        </el-table>
        <pagination v-show="path_total>=0" :total="path_total" :page.sync="page.pageNum" :limit.sync="page.pageSize" @pagination="getList" />
      </el-tab-pane>
      <el-tab-pane label="漏洞" name="vulner">
        <span slot="label">
          漏洞
          <el-badge v-show="vulner_label_total>0" :value="vulner_label_total" class="badge-a" />
        </span>
        <el-table :data="vulnerlist" :span-method="objectSpanMethod" border fit highlight-current-row style="width: 100%" @sort-change="vulnerSortChange">
          <el-table-column
            v-loading="loading"
            align="center"
            label="扫描ID"
            prop="scan_id"
            sortable="custom"
            :sort-orders="['ascending','descending']"
            width="100"
            element-loading-text="请给我点时间！"
          >
            <template slot-scope="{row}">
              <span>{{ row.scan_id }}</span>
            </template>
          </el-table-column>

          <el-table-column align="center" label="扫描时间">
            <template slot-scope="{row}">
              <span>{{ row.scan_time | parseTime('{y}-{m}-{d} {h}:{i}') }}</span>
            </template>
          </el-table-column>

          <el-table-column align="center" label="漏洞名称">
            <template slot-scope="{row}">
              <span>{{ row.vulner_name }}</span>
            </template>
          </el-table-column>

          <el-table-column align="center" label="漏洞描述">
            <template slot-scope="{row}">
              <span>{{ row.vulner_descrip }}</span>
            </template>
          </el-table-column>
        </el-table>
        <pagination v-show="vulner_total>=0" :total="vulner_total" :page.sync="page.pageNum" :limit.sync="page.pageSize" @pagination="getList" />
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
      portlist: null,
      pathlist: null,
      vulnerlist: null,
      spanArr: [],
      pos: 0,
      target: '',
      targetdata: {
        'scan_status': '',
        'scan_schedule': '',
        'vulner_number': '',
        'finger': ''
      },
      domain_total: 0,
      port_total: 0,
      path_total: 0,
      vulner_total: 0,
      domain_label_total: 0,
      port_label_total: 0,
      path_label_total: 0,
      vulner_label_total: 0,
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
        this.portlist = response.data.port.result
        this.domainlist = response.data.domain.result
        this.pathlist = response.data.path.result
        this.vulnerlist = response.data.vulner.result
        this.getSpanArr()
        this.domain_total = response.data.domain.total
        this.domain_label_total = response.data.domain.label_toal

        this.port_total = response.data.port.total
        this.port_label_total = response.data.port.label_toal

        this.path_total = response.data.path.total
        this.path_label_total = response.data.path.label_toal

        this.vulner_total = response.data.vulner.total
        this.vulner_label_total = response.data.vulner.label_toal
        this.loading = false
      })
    },
    getSpanArr() {
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
          if (this.domainlist[i].scan_id === this.domainlist[j].scan_id) {
            this.domainlist[i].rowspan++
            this.domainlist[j].rowspan--
          }
        }
        // 这里跳过已经重复的数据
        i = i + this.domainlist[i].rowspan - 1
      }
      this.portlist.forEach(v => {
        v.rowspan = 1
      })
      // 双层循环
      for (let i = 0; i < this.portlist.length; i++) {
        // 内层循环，上面已经给所有的行都加了v.rowspan = 1
        // 这里进行判断
        // 如果当前行的id和下一行的id相等
        // 就把当前v.rowspan + 1
        // 下一行的v.rowspan - 1
        for (let j = i + 1; j < this.portlist.length; j++) {
          // 此处可根据相同字段进行合并，此处是根据的id
          if (this.portlist[i].scan_id === this.portlist[j].scan_id) {
            this.portlist[i].rowspan++
            this.portlist[j].rowspan--
          }
        }
        // 这里跳过已经重复的数据
        i = i + this.portlist[i].rowspan - 1
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
          if (this.pathlist[i].scan_id === this.pathlist[j].scan_id) {
            this.pathlist[i].rowspan++
            this.pathlist[j].rowspan--
          }
        }
        // 这里跳过已经重复的数据
        i = i + this.pathlist[i].rowspan - 1
      }

      this.vulnerlist.forEach(v => {
        v.rowspan = 1
      })
      // 双层循环
      for (let i = 0; i < this.vulnerlist.length; i++) {
        // 内层循环，上面已经给所有的行都加了v.rowspan = 1
        // 这里进行判断
        // 如果当前行的id和下一行的id相等
        // 就把当前v.rowspan + 1
        // 下一行的v.rowspan - 1
        for (let j = i + 1; j < this.vulnerlist.length; j++) {
          // 此处可根据相同字段进行合并，此处是根据的id
          if (this.vulnerlist[i].scan_id === this.vulnerlist[j].scan_id) {
            this.vulnerlist[i].rowspan++
            this.vulnerlist[j].rowspan--
          }
        }
        // 这里跳过已经重复的数据
        i = i + this.vulnerlist[i].rowspan - 1
      }
    },
    objectSpanMethod({ row, column, rowIndex, columnIndex }) {
      if (columnIndex === 0) {
        return {
          rowspan: row.rowspan,
          colspan: 1
        }
      }
    },
    domainSortChange({ prop, order }) {
      this.domainlist.sort(this.compare(prop, order))
    },
    portSortChange({ prop, order }) {
      this.portlist.sort(this.compare(prop, order))
    },
    pathSortChange({ prop, order }) {
      this.pathlist.sort(this.compare(prop, order))
    },
    vulnerSortChange({ prop, order }) {
      this.vulnerlist.sort(this.compare(prop, order))
    },
    compare(propertyName, sort) {
      return function(obj1, obj2) {
        var value1 = obj1[propertyName]
        var value2 = obj2[propertyName]
        if (typeof value1 === 'string' && typeof value2 === 'string') {
          const res = value1.localeCompare(value2, 'zh')
          return sort === 'ascending' ? res : -res
        } else {
          if (value1 <= value2) {
            return sort === 'ascending' ? -1 : 1
          } else if (value1 > value2) {
            return sort === 'ascending' ? 1 : -1
          }
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
