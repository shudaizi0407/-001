<?php

namespace app\index\controller;
//由于写在了tp框架中 原生的代码可以看pay2.php

//具体参数在 pay2.php也做了详细解释

class Pay
{
//    微信商户的必要信息  可以再申请商户的邮件和微信公众品台中找到
    const MCHID = '1600****96';
    const APPID = 'w*****18';
    const APIKEY = 'Ice*****54443*****';

    public function __construct()
    {
        $this->mchid = self::MCHID;
        $this->appid = self::APPID;
        $this->apiKey = self::APIKEY;
    }

    public function pay()
    {
//接收传递参数
        $param = [];
        $payAmount = 29.9; //金额
        $orderName = '标题';
        $mchid = self::MCHID;
        $appid = self::APPID;
        $apiKey = self::APIKEY;
//        实例化自身 其实不需要 按自己的业务需求来   建议 使用self::   或者框架的$this
        $wxPay = new Pay($mchid, $appid, $apiKey);
        $outTradeNo = date('YmdHis') . uniqid();     //你自己的商品订单号

        //订单标题
        $notifyUrl = $_SERVER['SERVER_NAME'] . '/index/pay/repay';     //付款成功后的回调地址(不要有问号)
        $payTime = time();      //付款时间
//     $data   这里是我业务需求的参数  根据业务需求来
        $data = [

        ];


//这个是主要接口   传递必要参数
        $arr = $wxPay->createJsBizPackage($payAmount, $outTradeNo, $orderName, $notifyUrl, $payTime);

        if (empty($info)) {
            $data['pay_code'] = $arr['code_url'];

            $isSuc = db('recharge')->insert($data);
        }

//后期维护人员注意
//        如果$arr 返回有7个数据 且有code_url 说明没问题 code_url 为二维码内容弄微信扫描后扣款
//        这里是扫码后的传递内容
        $res = [
            'ordername' => $orderName . '(123次)',

            'money' => $payAmount,
            'code' => 0,
            'staus' => 1,
            'code_url' => $arr['code_url']
        ];

        return json($res);
        exit();
    }
//支付回调


    /**
     * 发起订单
     * @param float $totalFee 收款总费用 单位元
     * @param string $outTradeNo 唯一的订单号
     * @param string $orderName 订单名称
     * @param string $notifyUrl 支付结果通知url 不要有问号
     * @param string $timestamp 订单发起时间
     * @return array
     */
    public function createJsBizPackage($totalFee, $outTradeNo, $orderName, $notifyUrl, $timestamp)
    {
        $config = array(
            'mch_id' => self::MCHID,
            'appid' => self::APPID,
            'key' => self::APIKEY,
        );


        //$orderName = iconv('GBK','UTF-8',$orderName);
        $unified = array(
            'appid' => $config['appid'],
            'attach' => '234234',             //商家数据包，原样返回，如果填写中文，请注意转换为utf-8
            'body' => $orderName,
            'mch_id' => $config['mch_id'],
            'nonce_str' => self::createNonceStr(),
            'notify_url' => $notifyUrl,
            'out_trade_no' => $outTradeNo,
            'spbill_create_ip' => '127.0.0.1',
            'total_fee' => intval($totalFee * 100),       //单位 转为分
            'trade_type' => 'NATIVE',
        );
        $unified['sign'] = self::getSign($unified, $config['key']);

        $responseXml = self::curlPost('https://api.mch.weixin.qq.com/pay/unifiedorder', self::arrayToXml($unified));

        //禁止引用外部xml实体
        libxml_disable_entity_loader(true);
        $unifiedOrder = simplexml_load_string($responseXml, 'SimpleXMLElement', LIBXML_NOCDATA);
        if ($unifiedOrder === false) {
            die('parse xml error');
        }
        if ($unifiedOrder->return_code != 'SUCCESS') {
            die($unifiedOrder->return_msg);
        }
        if ($unifiedOrder->result_code != 'SUCCESS') {
            die($unifiedOrder->err_code);
        }
        $codeUrl = (array)($unifiedOrder->code_url);
        if (!$codeUrl[0]) exit('get code_url error');
        $arr = array(
            "appId" => $config['appid'],
            "timeStamp" => $timestamp,
            "nonceStr" => self::createNonceStr(),
            "package" => "prepay_id=" . $unifiedOrder->prepay_id,
            "signType" => 'MD5',
            "code_url" => $codeUrl[0],
        );

        $arr['paySign'] = self::getSign($arr, $config['key']);

        return $arr;
    }

    public function check()
    {
        $member_id = session(config('USER_ID'));

        if (empty($member_id)) {
            $this->error('登录异常', 'login/index');
        }
        $member_order = db('recharge')
            ->where('member_id', $member_id)
            ->where('status', '1')
            ->where('issuc', '1')
            ->column('out_trade_no');
        if (empty($member_order)) {
            return true;
        }
        $config = array(
            'mch_id' => self::MCHID,
            'appid' => self::APPID,
            'key' => self::APIKEY,
        );
        foreach ($member_order as $key => $value) {
            $unified = array(
                'appid' => $config['appid'],
                'mch_id' => $config['mch_id'],
                "nonce_str" => self::createNonceStr(),
                'out_trade_no' => $value,
            );
            $unified['sign'] = self::getSign($unified, $config['key']);
            $responseXml = self::curlPost('https://api.mch.weixin.qq.com/pay/orderquery', self::arrayToXml($unified));
            libxml_disable_entity_loader(true);
            $unifiedOrder = simplexml_load_string($responseXml, 'SimpleXMLElement', LIBXML_NOCDATA);
            if ($unifiedOrder === false) {
                die('parse xml error');
            }
            if ($unifiedOrder->return_code != 'SUCCESS') {
                die($unifiedOrder->return_msg);
            }

            if ($unifiedOrder->trade_state == 'SUCCESS') {

                db()->startTrans();
                $mark = true;
                $data = [
                    'transaction_id' => $unifiedOrder->transaction_id,
                    'status' => '2',
                    'issuc' => '2',
                    'pay_time' => strtotime($unifiedOrder->time_end),
                ];

                $order = db('recharge')
                    ->where('out_trade_no', $value)
                    ->where('status', '1')
                    ->where('issuc', '1')
                    ->find();
                if (!empty($order)) {
                    $isSuc = db('recharge')->where('out_trade_no', $value)->update($data);
                    if ($isSuc != true) $mark = false;

                    $isSuc = db('member')->where('id', $member_id)->setInc('number', $order['number']);
                    if ($isSuc != true) $mark = false;
                    if ($mark) {
                        db()->commit();

                    } else {
                        db()->rollback();
                    }
                }

            }

        }
        return true;
    }

    public function repay()
    {
        $config = array(
            'mch_id' => self::MCHID,
            'appid' => self::APPID,
            'key' => self::APIKEY,
        );
        $postStr = $GLOBALS["HTTP_RAW_POST_DATA"];

        $postObj = simplexml_load_string($postStr, 'SimpleXMLElement', LIBXML_NOCDATA);
        if ($postObj === false) {
            die('parse xml error');
        }
        if ($postObj->return_code != 'SUCCESS') {
            die($postObj->return_msg);
        }
        if ($postObj->result_code != 'SUCCESS') {
            die($postObj->err_code);
        }
        $arr = (array)$postObj;
        unset($arr['sign']);
        if (self::getSign($arr, $config['key']) == $postObj->sign) {
            echo '<xml><return_code><![CDATA[SUCCESS]]></return_code><return_msg><![CDATA[OK]]></return_msg></xml>';
            return $postObj;
        }
    }

    /**
     * curl get
     *
     * @param string $url
     * @param array $options
     * @return mixed
     */
    public static function curlGet($url = '', $options = array())
    {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        if (!empty($options)) {
            curl_setopt_array($ch, $options);
        }
        //https请求 不验证证书和host
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        $data = curl_exec($ch);
        curl_close($ch);
        return $data;
    }

    public static function curlPost($url = '', $postData = '', $options = array())
    {
        if (is_array($postData)) {
            $postData = http_build_query($postData);
        }
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30); //设置cURL允许执行的最长秒数
        if (!empty($options)) {
            curl_setopt_array($ch, $options);
        }
        //https请求 不验证证书和host
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        $data = curl_exec($ch);
        curl_close($ch);
        return $data;
    }

    public static function createNonceStr($length = 16)
    {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $str = '';
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }

    public static function arrayToXml($arr)
    {
        $xml = "<xml>";
        foreach ($arr as $key => $val) {
            if (is_numeric($val)) {
                $xml .= "<" . $key . ">" . $val . "</" . $key . ">";
            } else
                $xml .= "<" . $key . "><![CDATA[" . $val . "]]></" . $key . ">";
        }
        $xml .= "</xml>";
        return $xml;
    }

    /**
     * 获取签名
     */
    public static function getSign($params, $key)
    {
        ksort($params, SORT_STRING);
        $unSignParaString = self::formatQueryParaMap($params, false);
        $signStr = strtoupper(md5($unSignParaString . "&key=" . $key));
        return $signStr;
    }

    protected static function formatQueryParaMap($paraMap, $urlEncode = false)
    {
        $buff = "";
        ksort($paraMap);
        foreach ($paraMap as $k => $v) {
            if (null != $v && "null" != $v) {
                if ($urlEncode) {
                    $v = urlencode($v);
                }
                $buff .= $k . "=" . $v . "&";
            }
        }
        $reqPar = '';
        if (strlen($buff) > 0) {
            $reqPar = substr($buff, 0, strlen($buff) - 1);
        }
        return $reqPar;
    }
}