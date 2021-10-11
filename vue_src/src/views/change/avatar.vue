<template>
  <div class="components-container">
    <pan-thumb :image="image" />

    <el-button type="primary" icon="el-icon-upload" style="position: absolute;bottom: 15px;margin-left: 40px;" @click="imagecropperShow=true">
      选择图片
    </el-button>

    <image-cropper
      v-show="imagecropperShow"
      :key="imagecropperKey"
      :width="300"
      :height="300"
      lang-type="en"
      @close="close"
      @crop-upload-success="cropSuccess"
    />
  </div>
</template>

<script>
import ImageCropper from '@/components/ImageCropper'
import PanThumb from '@/components/PanThumb'
import { Encrypt } from '@/utils/rsa'
import { getToken } from '@/utils/auth'
import { changeAvatar } from '@/api/user'

export default {
  name: 'AvatarUploadDemo',
  components: { ImageCropper, PanThumb },
  data() {
    return {
      imagecropperShow: false,
      imagecropperKey: 0
    }
  },
  computed: {
    image() {
      return this.$store.getters.avatar
    }
  },
  methods: {
    cropSuccess(resData) {
      this.imagecropperShow = false
      this.imagecropperKey = this.imagecropperKey + 1
      this.$store.commit('user/SET_AVATAR', '/api/images/' + resData)
      let data = {
        'imagename': resData,
        'token': getToken()
      }
      data = JSON.stringify(data)
      const params = {
        'data': Encrypt(data)
      }
      changeAvatar(params).then(response => {
      })
    },
    close() {
      this.imagecropperShow = false
    }
  }
}
</script>

<style scoped>
  .avatar{
    width: 200px;
    height: 200px;
    border-radius: 50%;
  }
</style>

