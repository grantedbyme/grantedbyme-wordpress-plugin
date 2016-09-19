<?php

// load composer class loader
require_once('vendor/autoload.php');

// load wordpress functions
if (!function_exists('get_user_by')) {
    include('../../../wp-config.php');
}

use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$ajax = new GrantedByMeWPCallback();

/**
 * GrantedByMe WordPress Plug-In Callback
 *
 * PHP version 5
 *
 * @category PlugIn
 * @package  GBM
 * @author   GrantedByMe <info@grantedby.me>
 * @access   private
 * @license  https://grantedby.me/licenses/php/license.md MIT
 * @version  Release: <release_id>
 * @link     https://grantedby.me
 */
class GrantedByMeWPCallback
{
    private static $ALLOWED_OPERATIONS = array('ping', 'unlink_account', 'rekey_account');
    private static $LOGGER;

    /**
     * Constructor
     */
    function __construct()
    {
        if(!isset(self::$LOGGER)) {
            self::$LOGGER = new Logger('GrantedByMeWPCallback');
            self::$LOGGER->pushHandler(new StreamHandler(__DIR__ . '/data/app.log', Logger::INFO));
        }
        //self::$LOGGER->addInfo('Callback', $_REQUEST);
        //$headers = getallheaders();
        //self::$LOGGER->addInfo('Headers', $headers);
        if (!isset($_POST['signature']) || !isset($_POST['payload'])) {
            $this->gbm_error('Encryption error');
        }
        $cipherRequest = array();
        $cipherRequest['signature'] = $_POST['signature'];
        $cipherRequest['payload'] = $_POST['payload'];
        if(isset($_POST['message'])) {
            $cipherRequest['message'] = $_POST['message'];
        }
        $gbm = GrantedByMeWP::init_sdk();
        $plainRequest = $gbm->getCrypto()->decrypt_json($cipherRequest);
        self::$LOGGER->addInfo('Request', $plainRequest);
        if (!isset($plainRequest['operation'])) {
            $this->gbm_error('Operation not set');
        }
        if (!in_array($plainRequest['operation'], self::$ALLOWED_OPERATIONS)) {
            $this->gbm_error('Operation not allowed: ' . $plainRequest['operation']);
        }
        $is_success = false;
        $operation = $plainRequest['operation'];
        $response = array();
        if ($operation == 'ping') {
            $is_success = true;
        } else if ($operation == 'unlink_account') {
            $options = get_option('grantedbyme_option_name');
            foreach ($options['users'] as $key => $value) {
                if (hash('sha512', $value) == $plainRequest['token']) {
                    self::$LOGGER->addInfo('Unlink account: ' . $key);
                    unset($options['users'][$key]);
                    $is_success = update_option('grantedbyme_option_name', $options);
                    break;
                }
            }
        } else if ($operation == 'rekey_account') {
            $options = get_option('grantedbyme_option_name');
            foreach ($options['users'] as $key => $value) {
                if (hash('sha512', $value) == $plainRequest['token']) {
                    $response['grantor'] = $value;
                    break;
                }
            }
        }
        self::$LOGGER->addInfo($operation . ' => ' . $is_success);
        $response['success'] = $is_success;
        die($gbm->getCrypto()->encrypt_json(json_encode($response)));
    }

    /**
     * Generic error handler
     */
    private function gbm_error($reason)
    {
        self::$LOGGER->addInfo('gbm_error: ' . $reason);
        $response = array();
        $response['success'] = false;
        header('HTTP/1.0 400 Bad Request');
        die(json_encode($response));
    }

}
