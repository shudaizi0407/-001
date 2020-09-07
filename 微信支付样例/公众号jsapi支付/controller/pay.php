<?php
//适用于tp5框架 可以直接使用
namespace app\weixin\controller;

/**
 * 适用于jsapi支付
 */
header('Content-type:text/html; Charset=utf-8');

class Pay
{

    const MCHID = '160***3962';//微信支付商户号 PartnerID 通过微信支付商户资料审核后邮件发送
    const APPID = 'wxcabb*****a8094'; //微信支付申请对应的公众号的APPID
    //设置的 APIKEY
    const APIKEY = '54DD4E3A****A356F16631B929';  //https://pay.weixin.qq.com 帐户设置-安全设置-API安全-API密钥-设置API密钥
    const APPKEY = '80*****7d687*****cc9d8';   //微信支付申请对应的公众号的APP Key
    const DATA = null;
//操作密码
//150581

    public function __construct()
    {
        $this->mchid = self::MCHID; //https://pay.weixin.qq.com 产品中心-开发配置-商户号
        $this->appid = self::APPID; //微信支付申请对应的公众号的APPID
        $this->appKey = self::APPKEY;
        $this->apiKey = self::APIKEY;   //https://pay.weixin.qq.com 帐户设置-安全设置-API安全-API密钥-设置API密钥
        $this->data = self::DATA;;
    }

    public function index()
    {
//        接受传递参数
        $param = [];
//        使用封装的方式获取openid
        $openId = $this->GetOpenid();
        if (!$openId) exit('获取openid失败');
//        $order_info 订单相关信息
        $order_info = [];

        $outTradeNo = $order_info['order_number'];     //你自己的商品订单号
        $payAmount = $order_info['price'] + $order_info['price_freight'];          //付款金额，单位:元

        $orderName = '购买货物';    //订单标题
        $notifyUrl = 'https://zhihuimiaoyi.com/weixin/pay/notify';     //付款成功后的回调地址(不要有问号)
        $payTime = time();      //付款时间

        $jsApiParameters = $this->createJsBizPackage($openId, $payAmount, $outTradeNo, $orderName, $notifyUrl, $payTime);

        $jsApiParameters = json_encode($jsApiParameters);
        return view('index', [
//            传递给前端的必要参数
            'jsApiParameters' => $jsApiParameters,
            'payAmount' => $payAmount
        ]);
    }


    public function notify()
    {
        $param = input();
        $id = $param['id'];
        $where[] = ['id', 'eq', $id];
//        $where[] = ['order_number','eq',$order_number];

        $order_info = Db::name('order')->where($where)->find();

        $config = array(
            'mch_id' => self::MCHID,
            'appid' => self::APPID,
            'key' => self::APIKEY,
        );


        $unified = array(
            'appid' => $config['appid'],
            'mch_id' => $config['mch_id'],
            "nonce_str" => self::createNonceStr(),
            'out_trade_no' => $order_info['order_number'],
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
            $transaction_id = $unifiedOrder->transaction_id;
//            传递的transaction_id为对象格式 这里处理一下
            if (!is_array($transaction_id)) {
                $transaction_id = json_encode($transaction_id);
                $transaction_id = json_decode($transaction_id, true);
                $transaction_id = $transaction_id['0'];
            }
//支付成功的操作

        }
        return true;

    }

    /**
     * 通过跳转获取用户的openid，跳转流程如下：
     * 1、设置自己需要调回的url及其其他参数，跳转到微信服务器https://open.weixin.qq.com/connect/oauth2/authorize
     * 2、微信服务处理完成之后会跳转回用户redirect_uri地址，此时会带上一些参数，如：code
     * @return 用户的openid
     */
    public function GetOpenid()
    {
        //通过code获得openid
        if (!isset($_GET['code'])) {
            //触发微信返回code码
            $scheme = 'http://';
            $uri = $_SERVER['PHP_SELF'] . $_SERVER['QUERY_STRING'];
            if ($_SERVER['REQUEST_URI']) $uri = $_SERVER['REQUEST_URI'];
            $baseUrl = urlencode($scheme . $_SERVER['HTTP_HOST'] . $uri);

            $url = $this->__CreateOauthUrlForCode($baseUrl);

            Header("Location: $url");
            exit();
        } else {
            //获取code码，以获取openid
            $code = $_GET['code'];
            $openid = $this->getOpenidFromMp($code);
            return $openid;
        }
    }

    /**
     * 通过code从工作平台获取openid机器access_token
     * @param string $code 微信跳转回来带上的code
     * @return openid
     */
    public function GetOpenidFromMp($code)
    {
        $url = $this->__CreateOauthUrlForOpenid($code);
        $res = self::curlGet($url);
        //取出openid
        $data = json_decode($res, true);
        if (!isset($data['openid'])) {
            $this->error('此页面不可刷新', 'my/order', '', '1');
        }
        $openid = $data['openid'];

        $this->data = $data;

        return $openid;
    }

    /**
     * 构造获取open和access_toke的url地址
     * @param string $code，微信跳转带回的code
     * @return 请求的url
     */
    private function __CreateOauthUrlForOpenid($code)
    {
        $urlObj["appid"] = $this->appid;
        $urlObj["secret"] = $this->appKey;
        $urlObj["code"] = $code;
        $urlObj["grant_type"] = "authorization_code";
        $bizString = $this->ToUrlParams($urlObj);
        return "https://api.weixin.qq.com/sns/oauth2/access_token?" . $bizString;
    }

    /**
     * 构造获取code的url连接
     * @param string $redirectUrl 微信服务器回跳的url，需要url编码
     * @return 返回构造好的url
     */
    private function __CreateOauthUrlForCode($redirectUrl)
    {
        $urlObj["appid"] = $this->appid;
        $urlObj["redirect_uri"] = "$redirectUrl";
        $urlObj["response_type"] = "code";
        $urlObj["scope"] = "snsapi_base";
        $urlObj["state"] = "STATE" . "#wechat_redirect";
        $bizString = $this->ToUrlParams($urlObj);
        return "https://open.weixin.qq.com/connect/oauth2/authorize?" . $bizString;
    }

    /**
     * 拼接签名字符串
     * @param array $urlObj
     * @return 返回已经拼接好的字符串
     */
    private function ToUrlParams($urlObj)
    {
        $buff = "";
        foreach ($urlObj as $k => $v) {
            if ($k != "sign") $buff .= $k . "=" . $v . "&";
        }
        $buff = trim($buff, "&");
        return $buff;
    }

    /**
     * 统一下单
     * @param string $openid 调用【网页授权获取用户信息】接口获取到用户在该公众号下的Openid
     * @param float $totalFee 收款总费用 单位元
     * @param string $outTradeNo 唯一的订单号
     * @param string $orderName 订单名称
     * @param string $notifyUrl 支付结果通知url 不要有问号
     * @param string $timestamp 支付时间
     * @return string
     */
    public function  createJsBizPackage($openid, $totalFee, $outTradeNo, $orderName, $notifyUrl, $timestamp)
    {
        $config = array(
            'mch_id' => $this->mchid,
            'appid' => $this->appid,
            'key' => $this->apiKey,
        );

        $unified = array(
            'appid' => $config['appid'],
            'attach' => 'pay',             //商家数据包，原样返回，如果填写中文，请注意转换为utf-8
            'body' => $orderName,
            'mch_id' => $config['mch_id'],
            'nonce_str' => self::createNonceStr(),
            'notify_url' => $notifyUrl,
            'openid' => $openid,            //rade_type=JSAPI，此参数必传
            'out_trade_no' => $outTradeNo,
            'spbill_create_ip' => '127.0.0.1',
            'total_fee' => intval($totalFee * 100),       //单位 转为分
            'trade_type' => 'JSAPI',
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
        $arr = array(
            "appId" => $config['appid'],
            "timeStamp" => "$timestamp",        //这里是字符串的时间戳，不是int，所以需加引号
            "nonceStr" => self::createNonceStr(),
            "package" => "prepay_id=" . $unifiedOrder->prepay_id,
            "signType" => 'MD5',
        );
        $arr['paySign'] = self::getSign($arr, $config['key']);
        return $arr;
    }

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