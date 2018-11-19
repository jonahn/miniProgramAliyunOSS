const env = require('./aliyunEnv.js');

const Base64 = require('../tool/Base64.js');

require('../tool/hmac.js');
require('../tool/sha1.js');
const Crypto = require('../tool/crypto.js');

const uploadFile = function (dir, filePath, successCB, errorCB) {
    if (!filePath) {
        wx.showModal({
            title: '文件错误',
            content: '请重试',
            showCancel: false,
        })
        return;
    }
  let key = filePath.replace('http://tmp/', 'mini_program');
  let fileName = key.replace('wxfile://tmp', 'mini_program');
  const aliyunFileKey = env.OSSFileDic + dir  + fileName;
    const policyBase64 = getPolicyBase64();
    const signature = getSignature(policyBase64);
    wx.uploadFile({
        url: env.OSSHost,
        filePath: filePath,
        name: 'file',
        formData: {
            'key': aliyunFileKey,
            'OSSAccessKeyId': env.OSSAccessKeyId,
            'policy': policyBase64,
            'Signature': signature,
            'success_action_status': '200',
        },
        success: function (res) {
            if (res.statusCode != 200) {
                errorCB(new Error('上传错误:' + JSON.stringify(res)))
                return;
            }
            successCB(fileName);
        },
        fail: function (err) {
          errorCB(new Error('请求失败'))
        },
    })
}

const getPolicyBase64 = function () {
    let date = new Date();
    date.setHours(date.getHours() + env.TimeOut);
    let srcT = date.toISOString();
    const policyText = {
        "expiration": srcT, //设置该Policy的失效时间，超过这个失效时间之后，就没有办法通过这个policy上传文件了 指定了Post请求必须发生在2020年01月01日12点之前("2020-01-01T12:00:00.000Z")。
        "conditions": [
            ["content-length-range", 0, 10 * 1024 * 1024]
        ]
    };

    const policyBase64 = Base64.encode(JSON.stringify(policyText));
    return policyBase64;
}

const getSignature = function (policyBase64) {
  const accesskey = env.AccsessKeySecret;

    const bytes = Crypto.HMAC(Crypto.SHA1, policyBase64, accesskey, {
        asBytes: true
    });
    const signature = Crypto.util.bytesToBase64(bytes);

    return signature;
}

module.exports = uploadFile;