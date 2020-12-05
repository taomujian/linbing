<template>
  <Form ref = "SystemsetForm" :model="form" :rules="rules" @submit.native.prevent>
    <FormItem>
      <Select v-model="proxytype" clearable>
          <Option value="http">http 代理</Option>
          <Option value="socks4">socks4 代理</Option>
          <Option value="socks5">socks5 代理</Option>
      </Select>
    </FormItem>
    <FormItem prop="proxyip">
        <Input type="text" v-model="form.proxyip" placeholder="代理地址,比如127.0.0.1:8080" clearable>
          <span slot="prepend">
            <Icon :size="14" type="ios-add-circle-outline"/>
          </span>
        </Input>
    </FormItem>
    <FormItem prop="timeout">
        <Input type="text" v-model="form.timeout" placeholder="扫描超时时间" clearable>
          <span slot="prepend">
            <Icon :size="14" type="ios-add-circle-outline"/>
          </span>
        </Input>
    </FormItem>
    <FormItem>
      <Button @click="handleSubmit" type="primary" long>确定</Button>
    </FormItem>
  </Form>
</template>

<script>
import {isurl} from '@/libs/validate'
import RSA  from '@/libs/crypto'
import http  from '@/libs/http'
import {getToken} from '@/libs/util'
export default {
  name: 'SystemsetForm',
  props: {
    proxyipRules: {
      type: Array,
      default: () => {
        return [
          { required: false, trigger: 'blur', max: 100}
        ]
      }
    },
    timeoutRules: {
      type: Array,
      default: () => {
        return [
          { required: true, trigger: 'blur', max:100}
        ]
      }
    }
  },
  data () {
    return {
      proxytype: '',
      form: {
        proxyip: '',
        timeout: ''
      },
    }
  },
  computed: {
    rules () {
      return {
        proxyip: this.proxyipRules,
        timeout: this.timeoutRules
      }
    }
  },

  methods: {
    handleSubmit () {
     this.$refs.SystemsetForm.validate( (valid) => {
        if (valid) {
          this.$emit('on-success-valid', {
            proxyip: this.form.proxyip,
            proxytype: this.proxytype,
            timeout: this.form.timeout,
            token: getToken()
          })
        }
      })
    }
  }
}
</script>
