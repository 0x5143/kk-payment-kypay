/**
 * 签名相关接口集
 *
 * @author <a href="hqc2010@gmail.com">云景(Neil)</a>
 * @since 2013.09.27
 */

var crypto = require('crypto');
var fs = require('fs');
var ursa = require('ursa');

/**
 * 生成签名
 * @param {String} prestr 待签名的源字符串
 * @param {String} key_file 私钥文件所在路径
 * @return {String} 签名值
 */
exports.sign = function(prestr, key_file) {
    var pem = fs.readFileSync(key_file);
    var key = pem.toString('ascii');
    var signob = crypto.createSign('RSA-SHA1');
    signob.update(prestr, 'utf8');
    return signob.sign(key, 'base64');
};

/**
 * 验证签名
 * @param {String} prestr 需要签名的字符串
 * @param {String} sign 签名结果
 * @param {String} cert_file 支付宝公钥文件路径
 * @return {Boolean} 是否通过验证
 */
exports.verify = function(prestr, sign, cert_file) {
    var publicPem = fs.readFileSync(cert_file);
    var publicKey = publicPem.toString('ascii');
    
    var verifyob = crypto.createVerify('RSA-SHA1');
    verifyob.update(prestr, 'utf8');
    return verifyob.verify(publicKey, sign, 'base64');
};

/**
 * 解密消息
 */
exports.decrypt = function(prestr, key_file) {
    var pem = fs.readFileSync(key_file);
    var pubob = ursa.createPublicKey(pem, 'base64');
    return pubob.publicDecrypt(prestr, 'base64', 'utf8');
};

