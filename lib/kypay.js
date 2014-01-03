/**
 * 快用支付的应用内支付验证模块
 * 实现订单下行通知的签名验证算法
 * @author <a href="hqc2010@gmail.com">yunjing</a>
 * @since 2013.10.24
 */

var qs = require('querystring');

var fparams = require('./params.func');
var fsign = require('./sign.func');
var fmd5 = require('./md5.func');

/**
 * 注意：不要自行修改以下各值
 * 这些数值仅供参考，具体定义与支付服务商保持一致
 */
var kNotifyResponseCode = {
    "PARAM_LOSE" : -10, //参数丢失
    "SIGN_ERROR" : -11, //通知签名不正确或者数据包不完整
    "DECRYPT_ERROR" : -12, //通知数据解密错误
    "DEALSEQ_NOT_EQUAL" : -13, //开发商交易号不一致
    "NOT_DEFINED_CODE" : -14, //未定义的支付返回码
    "PAY_FAILED" : -1, //支付失败
    "PAY_TIMEOUT" : -2 //支付超时
};

function KY(conf) {
    this.conf = conf;
}

module.exports = KY;

/**
 * 生成订单签名
 * 由于快用支付说明文档里写明由快用支付平台自行完成,
 * 故不在支付验证服务器完成签名行为。
 */
KY.prototype.createSign = function(deviceid, orderid, subject, fee) {
    var json = {
        'game' : this.conf.partner,
        'uid' : deviceid,
        'subject' : subject,
        'fee' : fee,
        'dealseq' : orderid,
        'paytype' : 'alipaywap',
        'v' : this.conf.version
    };
    
    var params_filter = fparams.doParamFilter(json, [], false);
    var params_sort = fparams.doArgSort(params_filter);
    var prestr = fparams.createLinkString(params_sort);
    return fmd5.md5Sign(prestr, this.conf.secret);
};

/**
 * 校验支付服务商的订单完成通知签名
 * @param {JSON|String} params 订单通知请求参数
 * @param {Function} callback 签名算法验证回调
 *      1:{Boolean} 校验是否成功通过，若为true则签名及支付结果都为正确的，否则为false
 *      2:{String} 返回给支付服务商的文本结果
 *      3:{JSON} 解析之后的支付订单，属性名与支付商提供文档一致
 *      4:{Number} 支付结果代码，0代表成功，负值代表失败；具体含义参见常量定义kNotifyResponseCode
 */
KY.prototype.asyncVerifyNotify = function(remoteip, params, callback) {
    var json = (typeof params == 'string') ? qs.parse(params) : params;
    
    //验证消息参数是否完整
    if (!json.sign || !json.notify_data || !json.dealseq || !json.uid || !json.subject || !json.orderid || !json.v) {
        callback(false, 'failed', null, kNotifyResponseCode.PARAM_LOSE);
        return;
    }
    
    //验证签名
    var params_filter = fparams.doParamFilter(json, ['sign'], false);
    var params_sort = fparams.doArgSort(params_filter);
    var prestr = fparams.createLinkString(params_sort);
    
    //由于php的urlencode对空格进行时会变成+，所以特此处理
    //prestr = prestr.replace(/%20/g, '+');
    
    var is_sign_right = fsign.verify(prestr, json.sign, this.conf.cert_file);
    if (!is_sign_right) {
        callback(false, 'failed', null, kNotifyResponseCode.SIGN_ERROR);
        return;
    }
    
    //解密notify_data
    var str2 = fsign.decrypt(json.notify_data, this.conf.cert_file);
    var json2 = qs.parse(str2);
    if (!json2.dealseq || !json2.fee) {
        callback(false, 'failed', null, kNotifyResponseCode.DECRYPT_ERROR);
        return;
    }
    
    //数据不合理，开发商订单两个内容不一致
    if (json2.dealseq !== json.dealseq) {
        callback(false, 'failed', null, kNotifyResponseCode.DEALSEQ_NOT_EQUAL);
        return;
    }
    
    //生成订单对象
    var orderob = {
        'dealseq' : json2.dealseq,
        'fee' : json2.fee,
        'orderid' : json.orderid,
        'uid' : json.uid,
        'subject' : json.subject
    };
    
    var iresult = parseInt(json2.payresult, 10);
    switch (iresult) {
        case 0:
            callback(true, 'success', orderob);
            break;
        case -1:
            callback(false, 'success', orderob, kNotifyResponseCode.PAY_FAILED);
            break;
        case -2:
            callback(false, 'success', orderob, kNotifyResponseCode.PAY_TIMEOUT);
            break;
        default:
            callback(false, 'success', orderob, kNotifyResponseCode.NOT_DEFINED_CODE);
            break;
    }
};
