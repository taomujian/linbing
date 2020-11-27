<template>
  <Form ref = "NewtargetForm" :model="form" :rules="rules" @submit.native.prevent>
    <FormItem prop="target">
      <Input type="textarea" v-model="form.target" placeholder="请输入目标,格式如10.0.0.1或http://xxx.com或10.0.0.0/24" clearable>
        <span slot="prepend">
          <Icon :size="14" type="ios-add-circle-outline"/>
        </span>
      </Input>
    </FormItem>
    <FormItem prop="description">
      <Input type="textarea" v-model="form.description" placeholder="请输入关于目标的描述" clearable>
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
import {istarget} from '@/libs/validate'
import RSA  from '@/libs/crypto'
import http  from '@/libs/http'
import {getToken} from '@/libs/util'
export default {
  name: 'NewtargetForm',
  props: {
    targetRules: {
      type: Array,
      default: () => {
        return [
          { required: true, trigger: 'blur', validator: istarget, max:100}
        ]
      }
    },
    descriptionRules: {
      type: Array,
      default: () => {
        return [
          { required: false, trigger: 'blur', max: 100}
        ]
      }
    }
  },
  data () {
    return {
      capta: '',
      form: {
        target: '',
        description: ''
      },
    }
  },
  computed: {
    rules () {
      return {
        target: this.targetRules,
        description: this.descriptionRules
      }
    }
  },
  methods: {
    handleSubmit () {
     this.$refs.NewtargetForm.validate( (valid) => {
        if (valid) {
            this.form.target = this.form.target.split(/[(\r\n)\r\n]+/).join(';')
            this.$emit('on-success-valid', {
              target: this.form.target,
              description: this.form.description,
              token: getToken()
            })
        }
      })
    }
  }
}
</script>
