<template>
    <div class="div">
      <div class="demo-upload-list" v-for="item in uploadList">
        <template v-if="item.status === 'finished'">
            <img :src="item.url">
            <div class="demo-upload-list-cover">
                <Icon type="ios-eye-outline" @click.native="handleView(item.name)"></Icon>
                <Icon type="ios-trash-outline" @click.native="handleRemove(item)"></Icon>
            </div>
        </template>
        <template v-else>
            <Progress v-if="item.showProgress" :percent="item.percentage" hide-info></Progress>
        </template>
    </div>
      <Upload
      ref="handleUpload"
      :data="data"
      :on-success="handleSuccess"
      :before-upload="handleBeforeUpload"
      :show-upload-list="false"
      :format="['jpg','jpeg','png', 'gif']"
      :max-size="8192"
      :on-exceeded-size="handleMaxSize"
      :on-format-error="handleFormatError"
      name="file"
      type="drag"
      action="/api/upload"
      style="display: inline-block;width:100px;">
      <div style="width: 100px;height:58px;line-height: 58px;">
            <Icon type="ios-camera" size="20"></Icon>
      </div>
      </Upload>
      <div>
      <img :src="'/api/images/' + imgName " v-if="visible" style="margin-left: 25%;width: 30%">
      </div>
      <Button type="primary" @click="changeavatar" style='margin-top:  10px; margin-left: -3px;width:100px'>保存</Button>
      <Button @click="cancel" style="margin-top:  10px; margin-left: -200px;margin-left: 8px;width:100px">返回</Button>
    </div>
</template>

<script>
import RSA  from '@/libs/crypto'
import http  from '@/libs/http'
import {getToken } from '@/libs/util'
import store from '../../store'
export default {
  data(){
    return{
      imgName: '',
      visible: false,
      token: getToken(),
      data: { 
        'token': '',
      },
      uploadList: [],
    }
  },

  created() {
    // 在页面加载时读取sessionStorage里的状态信息
    if (sessionStorage.getItem('store')) {
      this.$store.replaceState(
        Object.assign(
          {},
          this.$store.state,
          JSON.parse(sessionStorage.getItem('store'))
        )
      )
    }
 
    // 在页面刷新时将vuex里的信息保存到sessionStorage里
    // beforeunload事件在页面刷新时先触发
    window.addEventListener('beforeunload', () => {
      sessionStorage.setItem('store', JSON.stringify(this.$store.state))
    })
  },
  
  methods: {
    handleView (name) {
      this.visible = true;
    },
    handleRemove (file) {
      const fileList = this.$refs.upload.fileList;
      this.$refs.upload.fileList.splice(fileList.indexOf(file), 1);
    },
    handleSuccess (res, file) {
      this.$Notice.success({
        title: '上传成功',
         desc: '图片上传成功'
      })
      res = eval('(' + res + ')')
      file.url = res.data.split('/')[3];
      file.name = res.data.split('/')[3];
      this.imgName = res.data.split('/')[3];
      this.visible=true
    },
    handleFormatError (file) {
      this.$Notice.warning({
          title: '上传文件格式错误',
          desc: '文件格式' + file.name + ' 错误,请重新上传,支持的文件格式为'
      });
    },
    handleMaxSize (file) {
      this.$Notice.warning({
          title: '超出文件大小限制',
          desc: 'File  ' + file.name + ' 文件太大,请不要超过8M'
      });
    },
    handleBeforeUpload (file) {
      if(this.uploadList.length >= 1){
          this.$Message.info("最多只能上传1个文件");
      }
      else{
          this.uploadList.push(file);
      }
      //return false;
    },
    handleUpload () { 
      // 上传文件
      /*const instance = axios.create({
            withCredentials: true
      })
      var formdata = new FormData()
      formdata.append('file', this.uploadList[0])
      formdata.append('token', this.token)
      instance({
              url: '/api/upload',
              method: 'post',
              data: formdata,
              headers: { 'Content-Type': 'multipart/form-data' },
          }).then((res) => {
            res.data = eval('(' + res.data + ')')
            switch(res.data.code ){
                case 'Z10010':
                this.$Notice.success({
                  title: '上传成功',
                  desc: res.data.message
                })

                break
                case 'Z1001':
                this.$Notice.error({
                  title: '系统异常',
                  desc: '系统发生异常,请稍后再次尝试'
                 })
                break
                case 'Z1004':
                this.$Notice.error({
                  title: '认证失败',
                  desc: '认证失败,请稍后再次尝试'
                })
                break
                case 'Z10011':
                this.$Notice.error({
                  title: '上传异常',
                  desc: '上传失败,请稍候重试!'
                })
                break
                case 'Z10012':
                this.$Notice.error({
                  title: '上传异常',
                  desc: '上传文件名为空,请添加文件名'
                })
                break
                case 'Z10013':
                this.$Notice.error({
                  title: '上传异常',
                  desc: '上传文件格式不正确,请稍候重试'
                })
                break
                default:
                break
            }
          })*/

    },
    changeavatar () {
      let data = {
        'imagename': this.imgName,
        'token': this.token.trim()
      }
      data = JSON.stringify(data)
      let params = {'data': RSA.Encrypt(data)}
      http.post('/api/changeavatar', params).then((res) => {
        res.data = eval('(' + res.data + ')')
        switch(res.data.code ){
          case'Z1000':
          this.$Notice.success({
              title: '修改头像成功',
              desc: res.data.message
          })
          store.commit('setAvatar', '/api/images/' + this.imgName)
          setTimeout(() => {
                this.$router.push({
                  path: '/home'
                })
              },2000)
          break
          case 'Z1001':
          this.$Notice.error({
              title: '修改头像失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1002':
          this.$Notice.error({
              title: '修改头像失败',
              desc: '系统发生异常,请稍后再次尝试'
          })
          break
          case 'Z1004':
          this.$Notice.error({
              title: '修改头像失败',
              desc: '认证失败,请稍后再次尝试'
          })
          break
          default:
          break
        }
      })
    },
    cancel () {
      setTimeout(() => {
        this.$router.push({
          path: '/home'
        })
      },1000)
    }
  },
  mounted (){
    this.data.token = this.token
  }
}
</script>

<style lang="less" scoped>
    .div{
      padding: 10px;
      text-align:center;
      margin-top: 10px;
      margin-left: auto;
      margin-right: auto;
    }
    .title{
        height:60px;line-height:60px;background:#fff;
        font-size: 20px;text-indent: 20px;
    }
    .ivu-form .ivu-form-item-label{
        text-align: justify !important
    }
    .iconlabelUrl {
        width: 240px;
        height: 120px;
    }
</style>