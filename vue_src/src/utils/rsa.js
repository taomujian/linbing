import JSEncrypt from 'jsencrypt'
// Convert a hex string to a byte array 16进制转byte数组

function hexToBytes(hex) {
  for (var bytes = [], c = 0; c < hex.length; c += 2) { bytes.push(parseInt(hex.substr(c, 2), 16)) }
  return bytes
}

JSEncrypt.prototype.encryptLong2 = function(string) {
  var k = this.getKey()
  try {
    var ct = '' // RSA每次加密最大117bytes，需要辅助方法判断字符串截取位置
    // 1.获取字符串截取点
    var bytes = []
    bytes.push(0)
    var byteNo = 0
    var len, c
    len = string.length
    var temp = 0
    for (var i = 0; i < len; i++) {
      c = string.charCodeAt(i)
      if (c >= 0x010000 && c <= 0x10FFFF) {
        byteNo += 4
      } else if (c >= 0x000800 && c <= 0x00FFFF) {
        byteNo += 3
      } else if (c >= 0x000080 && c <= 0x0007FF) {
        byteNo += 2
      } else {
        byteNo += 1
      }
      if ((byteNo % 117) >= 114 || (byteNo % 117) === 0) {
        if (byteNo - temp >= 114) {
          bytes.push(i)
          temp = byteNo
        }
      }
    }
    // 2.截取字符串并分段加密
    if (bytes.length > 1) {
      // eslint-disable-next-line no-redeclare
      for (var i = 0; i < bytes.length - 1; i++) {
        var str
        if (i === 0) {
          str = string.substring(0, bytes[i + 1] + 1)
        } else {
          str = string.substring(bytes[i] + 1, bytes[i + 1] + 1)
        }
        var t1 = k.encrypt(str)
        ct += t1
      }
      if (bytes[bytes.length - 1] !== string.length - 1) {
        var lastStr = string.substring(bytes[bytes.length - 1] + 1)
        ct += k.encrypt(lastStr)
      }
      return hexToBytes(ct)
    }
    var t = k.encrypt(string)
    var y = hexToBytes(t)
    return y
  } catch (ex) {
    return false
  }
}

function arrayBufferToBase64(buffer) {
  var binary = ''
  var bytes = new Uint8Array(buffer)
  var len = bytes.byteLength
  for (var i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return window.btoa(binary)
}

export function Encrypt(data) {
  const encrypt = new JSEncrypt()
  encrypt.setPublicKey('-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+UHO/FX+mqq68COGYqk82/3xw7vfhNJIM58lrjI0T+zXIx6AsaNgrelM7Z+raDIRDJvdObz6qVbJ5L1IhcreeZWUmEtmOetqtkF4i/rhthVFmSDAKyZi8a6/SulpU8bHEsi2M3gyp25pi7R68GzcAmm1yKCusOaABFa4M7vuC8wIDAQAB-----END PUBLIC KEY-----') // 公钥
  const getrsadata = arrayBufferToBase64(encrypt.encryptLong2(data)) // 将加密的数据转码为base64
  return getrsadata // 加密后的数据
}

export default {
  Encrypt
}

