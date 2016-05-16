<?php

// load composer class loader
require_once('vendor/autoload.php');

// load wordpress functions
if (!function_exists('get_user_by')) {
    include('../../../wp-config.php');
}

use Monolog\Logger;
use Monolog\Handler\StreamHandler;

$ajax = new GrantedByMeWPAjax();

/**
 * GrantedByMe WordPress Plug-In AJAX
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
class GrantedByMeWPAjax
{
    private static $ALLOWED_OPERATIONS = array('getAccountToken', 'getAccountState', 'getSessionToken', 'getSessionState', 'getRegisterToken', 'getRegisterState');
    private $log;

    /**
     * Constructor
     */
    function __construct()
    {
        $this->log = new Logger('GrantedByMeWPAjax');
        $this->log->pushHandler(new StreamHandler(__DIR__ . '/data/app.log', Logger::INFO));
        // get all request headers
        $headers = getallheaders();
        // get function (action)
        if (!isset($_POST['operation'])) {
            header('HTTP/1.0 400 Bad Request');
            $this->gbm_error();
        }
        $operation = $_POST['operation'];
        // validate request
        if (!isset($operation)
            || !in_array($operation, self::$ALLOWED_OPERATIONS)
            || !isset($_SERVER['HTTP_X_REQUESTED_WITH'])
            || strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) != 'xmlhttprequest'
            || !isset($headers['X-CSRFToken'])
            || !wp_verify_nonce($headers['X-CSRFToken'], 'csrf-token')
            || (($operation == 'getAccountState' || $operation == 'getSessionState' || $operation == 'getRegisterState')
                && (!isset($_POST['token']) || !is_string($_POST['token']) || empty($_POST['token'])))
            || (($operation == 'getAccountToken' || $operation == 'getAccountState')
                && !is_user_logged_in())
        ) {
            header('HTTP/1.0 400 Bad Request');
            $this->gbm_error();
        }
        // call api
        if ($operation == 'getAccountToken') {
            $response = GrantedByMeWP::init_sdk()->getAccountToken();
            die(json_encode($response));
        } else if ($operation == 'getAccountState') {
            $this->gbm_get_account_state();
        } else if ($operation == 'getSessionToken') {
            $response = GrantedByMeWP::init_sdk()->getSessionToken();
            die(json_encode($response));
        } else if ($operation == 'getSessionState') {
            $this->gbm_get_session_state();
        } else if ($operation == 'getRegisterToken') {
            $response = GrantedByMeWP::init_sdk()->getRegisterToken();
            die(json_encode($response));
        } else if ($operation == 'getRegisterState') {
            $this->gbm_get_register_state();
        } else {
            $this->gbm_error();
        }
    }

    /**
     * TBD
     *
     * @throws \GBM\ApiRequestException
     */
    private function gbm_get_account_state()
    {
        $response = GrantedByMeWP::init_sdk()->getSessionState($_POST['token']);
        if (isset($response['status']) && $response['status'] == \GBM\ApiRequest::$STATUS_VALIDATED) {
            $grantor = \GBM\ApiRequest::getRandomToken();
            $result = GrantedByMeWP::init_sdk()->linkAccount($_POST['token'], $grantor);
            if (isset($result['success']) && $result['success'] == true) {
                $user_id = get_current_user_id();
                $options = get_option('grantedbyme_option_name');
                $options['users'][$user_id] = $grantor;
                $is_saved = update_option('grantedbyme_option_name', $options);
            } else {
                $this->log->addInfo('User account link error: ' . $result['error']);
            }
        }
        die(json_encode($response));
    }

    /**
     * TBD
     *
     * @throws \GBM\ApiRequestException
     */
    private function gbm_get_session_state()
    {
        $response = GrantedByMeWP::init_sdk()->getSessionState($_POST['token']);
        if (isset($response['status']) && $response['status'] == \GBM\ApiRequest::$STATUS_VALIDATED) {
            if (isset($response['grantor'])) {
                $_SESSION['gbm_token'] = $_POST['token'];
                $this->gbm_login($response['grantor']);
                // do not send secret to frontend
                unset($response['grantor']);
            } else {
                $this->log->addInfo('Login error with empty grantor');
                header('HTTP/1.0 401 Unauthorized');
                $this->gbm_error();
            }
        }
        die(json_encode($response));
    }

    /**
     * TBD
     *
     * @throws \GBM\ApiRequestException
     */
    private function gbm_get_register_state()
    {
        $response = GrantedByMeWP::init_sdk()->getSessionState($_POST['token']);
        if (isset($response['status']) && $response['status'] == \GBM\ApiRequest::$STATUS_VALIDATED) {
            if (isset($response['data'])) {
                $this->gbm_register($response['data']);
                // do not send secret to frontend
                unset($response['data']);
            } else {
                $this->log->addInfo('Register error with empty data');
                header('HTTP/1.0 401 Unauthorized');
                $this->gbm_error();
            }
        }
        die(json_encode($response));
    }

    /**
     * Register WordPress user
     *
     * @param $data
     */
    private function gbm_register($data)
    {
        if (!empty($data)) {
            $this->log->addInfo('Register', $data);
            $count_data = count_users();
            $total_users = $count_data['total_users'] + 1;
            $user_login = 'gbm_user_' . $total_users;
            $user_pass = \GBM\ApiCrypto::randomString(16);
            $userdata = array(
                'user_email'  =>  $data['email'],
                'first_name'  =>  $data['first_name'],
                'last_name'  =>  $data['last_name'],
                'user_login'  =>  $user_login,
                'user_pass'   => $user_pass
            );
            $user_id = wp_insert_user($userdata) ;
            if (!is_wp_error($user_id)) {
                $this->log->addInfo('User created: ' . $user_id);
                $grantor = \GBM\ApiRequest::getRandomToken();
                $result = GrantedByMeWP::init_sdk()->linkAccount($_POST['token'], $grantor);
                if (isset($result['success']) && $result['success'] == true) {
                    $options = get_option('grantedbyme_option_name');
                    $options['users'][$user_id] = $grantor;
                    $is_saved = update_option('grantedbyme_option_name', $options);
                    $this->log->addInfo('User account linked: ' . $user_id);
                } else {
                    $this->log->addInfo('User account link error: ' . $result['error']);
                }
            } else {
                $this->log->addInfo('User registration error: ' . $user_id);
            }
        } else {
            $this->gbm_error();
        }
    }

    /**
     * Log-in WordPress user
     *
     * @param $grantor
     */
    private function gbm_login($grantor)
    {
        if (!empty($grantor)) {
            $options = get_option('grantedbyme_option_name');
            $user_id = array_search($grantor, $options['users'], true);
            $user = get_user_by('id', esc_attr($user_id));
            if ($user) {
                $this->log->addInfo('Login success with user_id: ' . $user_id);
                wp_set_current_user($user->ID, $user->user_login);
                wp_set_auth_cookie($user->ID);
                do_action('wp_login', $user->user_login);
            } else {
                $this->log->addInfo('Login error with grantor: ' . $grantor);
                header('HTTP/1.0 401 Unauthorized');
                $this->gbm_error();
            }
        } else {
            $this->gbm_error();
        }
    }

    /**
     * Generic error handler
     */
    private function gbm_error()
    {
        $response = array();
        $response['success'] = false;
        $response['error'] = 'Restricted access';
        die(json_encode($response));
    }

}
