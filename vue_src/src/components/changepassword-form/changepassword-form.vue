<template>
  
  <Form ref = "ChangepasswordForm" :model="form" :rules="rules" @keydown.enter.native="handleSubmit">
    <FormItem prop="oldpassword">
      <Input type="password" v-model="form.oldpassword" placeholder="请输入旧密码,8-16位大小写字母或数字">
        <span slot="prepend">
          <Icon :size="14" type="md-lock"></Icon>
        </span>
      </Input>
    </FormItem>
    <FormItem prop="newpassword">
      <Input type="password" v-model="form.newpassword" placeholder="请输入新密码,8-16位大小写字母或数字">
        <span slot="prepend">
          <Icon :size="14" type="md-lock"></Icon>
        </span>
      </Input>
    </FormItem>
    <FormItem prop="newpasswordconfirm">
      <Input type="password" v-model="form.newpasswordconfirm" placeholder="请再次输入新密码,8-16位大小写字母或数字">
        <span slot="prepend">
          <Icon :size="14" type="md-lock"></Icon>
        </span>
      </Input>
    </FormItem>
    <FormItem>
      <Button @click="handleSubmit" type="primary" long>确定修改</Button>
    </FormItem>
  </Form>
</template>

<script>
import {isemail, isusername, ischecknum, ispassword} from '@/libs/validate'
import RSA  from '@/libs/crypto'
import AES  from '@/libs/AES'
import http  from '@/libs/http'
import {getToken } from '@/libs/util'
export default {
  name: 'ChangepasswordForm',
  props: {
    oldpasswordRules: {
      type: Array,
      default: () => {
        return [
          { required: true, trigger: 'blur', validator: ispassword }
        ]
      }
    },
    newpasswordRules: {
      type: Array,
      default: () => {
        return [
          { required: true, trigger: 'blur', validator: ispassword }
        ]
      }
    },
    newpasswordconfirmRules: {
      type: Array,
      default: () => {
        return [
          { required: true, trigger: 'blur', validator: ispassword }
        ]
      }
    }
  },
  data () {
    return {
      capta: '',
      form: {
        oldpassword: '',
        newpassword: '',
        newpasswordconfirm: ''
      }
    }
  },
  computed: {
    rules () {
      return {
        oldpassword: this.oldpasswordRules,
        newpassword: this.newpasswordRules,
        newpasswordconfirm: this.newpasswordconfirmRules
      }
    }
  },
  methods: {
    getchecknum () {
      if (this.form.email== ''){
        this.$refs.ChangepasswordForm.validateField('email', (valid) => {
        })
      }
      else{
        let data = {
          'type': 'email', 
          'data': this.form.email
        }
        data = JSON.stringify(data)
        let params = {'data': RSA.Encrypt(data)}
        http.post('/api/getchecknum', params).then((res) => {
          res.data = eval('(' + res.data + ')')
          switch(res.data.code ){
            case'Z1000':
            this.$Notice.success({
                title: '发送邮件成功',
                desc: '请打开邮件查收验证码 '
            })
            this.capta = AES.Decrypt(res.data.data)
            break
            case 'Z1001':
            this.$Notice.error({
                title: '发送邮件失败',
                desc: '系统发生异常,请稍后再次尝试'
            })
            break
            case 'Z1002':
            this.$Notice.error({
                title: '发送邮件失败',
                desc: '系统发生异常,请稍后再次尝试'
            })
            break
          }
        })
      }
    },
    handleSubmit () {
     this.$refs.ChangepasswordForm.validate( (valid) => {
        if (valid) {
          if (this.form.newpassword != this.form.newpasswordconfirm){
            this.$Notice.error({
                title: '二次密码输入不一样',
                desc: '二次密码输入不一样,请重新输入!'
            })
          }
          else{
            this.$emit('on-success-valid', {
              oldpassword: this.form.oldpassword,
              newpassword: this.form.newpassword,
              token: getToken()
            })
          }
        }
      })
    }
  }  
}
</script>
