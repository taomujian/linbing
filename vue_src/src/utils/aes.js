const CryptoJS = require('crypto-js') // 引用AES源码js

const key = CryptoJS.enc.Utf8.parse('FeEt54f434R23sVb') // 十六位十六进制数作为秘钥
const iv = CryptoJS.enc.Utf8.parse('Dew245fGhJZ9S12n') // 十六位十六进制数作为秘钥偏移量

// 解密方法
export function Decrypt(word) {
  const decrypt = CryptoJS.AES.decrypt(word, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 })
  const decryptedStr = decrypt.toString(CryptoJS.enc.Utf8)
  return decryptedStr.toString()
}
// 加密方法
export function Encrypt(word) {
  var srcs = CryptoJS.enc.Utf8.parse(word)
  var encrypted = CryptoJS.AES.encrypt(srcs, key, { iv: iv, mode: CryptoJS.mode.CBC, padding: CryptoJS.pad.Pkcs7 })
  var hexStr = encrypted.ciphertext.toString().toUpperCase()
  var oldHexStr = CryptoJS.enc.Hex.parse(hexStr)
  // 将密文转为Base64的字符串
  var base64Str = CryptoJS.enc.Base64.stringify(oldHexStr)
  return base64Str
}
export default {
  Decrypt,
  Encrypt
}
