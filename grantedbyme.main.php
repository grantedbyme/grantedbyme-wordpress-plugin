<?php

use Monolog\Logger;
use Monolog\Handler\StreamHandler;

/**
 * GrantedByMe WordPress Plug-In Main
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
class GrantedByMeWP
{
    private static $is_initialized = false;

    /**
     * GrantedByMe Options
     */
    private static $options;
    /**
     * GrantedByMe SDK
     */
    private static $gbm;
    /**
     * Monolog Logger
     */
    private static $log;

    public static function init()
    {
        if (!self::$is_initialized) {
            // start session if not exists
            if( !session_id() ) {
                session_start();
            }
            // get reference to plugin settings array
            self::$options = get_option('grantedbyme_option_name');
            // initialize gbm sdk
            self::init_sdk();
            // setup wp site hooks
            self::init_hooks();
        }
    }

    /**
     * Logging helper method
     */
    private static function log_info($message)
    {
        $IS_LOG_ENABLED = GBM_VERSION == '0.0.1-local';
        if($IS_LOG_ENABLED) {
            if(!isset(self::$log)) {
                self::$log = new Logger('GrantedByMeWP');
                self::$log->pushHandler(new StreamHandler(GBM_PLUGIN_DIR . 'data/app.log', Logger::INFO));
            }
            self::$log->addInfo($message);
        }
    }

    /**
     * Initializes WordPress hooks
     */
    private static function init_hooks()
    {
        // allow to run only once
        self::$is_initialized = true;
        // check for activated plugin
        if (self::$gbm->isActivated()) {
            // common
            add_action('init', array('GrantedByMeWP', 'gbm_init'));
            add_action('wp_loaded', array('GrantedByMeWP', 'gbm_loaded'));
            // commenting
            add_action('comment_form', array('GrantedByMeWP', 'gbm_comment_form'));
            add_filter('preprocess_comment', array('GrantedByMeWP', 'gbm_comment_validate'));
            // authenticating
            add_action('login_form', array('GrantedByMeWP', 'gbm_login_form'));
            add_filter('wp_authenticate_user', array('GrantedByMeWP', 'gbm_login_validate'), 10, 2);
            add_action('wp_logout', array('GrantedByMeWP', 'gbm_logout'));
            // registering
            add_action('register_form', array('GrantedByMeWP', 'gbm_register_form'));
            add_filter('registration_errors', array('GrantedByMeWP', 'gbm_register_validate'), 10, 3);
            add_action('user_register', array('GrantedByMeWP', 'gbm_user_register'), 10, 1);
            // common
            add_shortcode('gbm_widget', array('GrantedByMeWP', 'gbm_widget_render'));
            add_action('wp_enqueue_scripts', array('GrantedByMeWP', 'gbm_enqueue_asset'));
            add_action('login_enqueue_scripts', array('GrantedByMeWP', 'gbm_enqueue_asset'));
            add_action('admin_enqueue_scripts', array('GrantedByMeWP', 'gbm_check_session'));
            // extension for /wp-admin/users.php
            add_action('user_new_form', array('GrantedByMeWP', 'gbm_user_new_form'));
            add_action('wpmu_new_user', array('GrantedByMeWP', 'gbm_wpmu_new_user'));
            add_action('delete_user', array('GrantedByMeWP', 'gbm_delete_user'));
            add_action('deleted_user', array('GrantedByMeWP', 'gbm_deleted_user'));
            add_action('wpmu_delete_user', array('GrantedByMeWP', 'gbm_wpmu_delete_user'));
            add_filter('manage_users_columns', array('GrantedByMeWP', 'gbm_add_user_columns'));
            add_action('manage_users_custom_column', array('GrantedByMeWP', 'gbm_show_user_id_column_content'), 10, 3);
        }
    }

    /**
     * Initializes the GrantedByMeSDK
     */
    public static function init_sdk()
    {
        $base_dir = GBM_PLUGIN_DIR . 'data/';
        if (file_exists($base_dir . 'service_private_key.pem')) {
            $private_key = file_get_contents($base_dir . 'service_private_key.pem');
            $server_key = file_get_contents($base_dir . 'server_public_key.pem');
        } else if (
            isset(self::$options['private_key']) &&
            isset(self::$options['server_key'])
        ) {
            $private_key = self::$options['private_key'];
            $server_key = self::$options['server_key'];
        } else {
            $private_key = false;
            $server_key = false;
        }
        if (isset(self::$options['api_url'])) {
            $api_url = self::$options['api_url'];
        } else {
            $api_url = \GBM\ApiSettings::$HOST;
        }
        $config = array();
        $config['private_key'] = $private_key;
        $config['public_key'] = $server_key;
        $config['api_url'] = $api_url;
        self::$gbm = new \GBM\ApiRequest($config);
        return self::$gbm;
    }

    /**
     * Returns the GBM SDK instance
     *
     * @return mixed
     */
    public static function gbm_get_sdk()
    {
        return self::$gbm;
    }

    ////////////////////////////////////////
    // Plugin Activation and Deactivation
    ////////////////////////////////////////

    /**
     * Triggered when the plugin is activated
     * @return bool
     */
    public static function gbm_plugin_activation()
    {
        //self::log_info('gbm_plugin_activation');
        return true;
    }

    /**
     * Triggered when the plugin is deactivated
     * @return bool
     */
    public static function gbm_plugin_deactivation()
    {
        //self::log_info('gbm_plugin_deactivation');
        return true;
    }

    ////////////////////////////////////////
    // User Create
    ////////////////////////////////////////

    /**
     * TBD
     * @param $user_id
     */
    public static function gbm_user_new_form($user_id)
    {
        self::log_info('gbm_user_new_form: ' . $user_id);
    }

    /**
     * TBD
     * @param $user_id
     */
    public static function gbm_wpmu_new_user($user_id)
    {
        self::log_info('gbm_wpmu_new_user: ' . $user_id);
    }

    ////////////////////////////////////////
    // User Delete
    ////////////////////////////////////////

    /**
     * Triggered before the User gets delete from the database
     * @param $user_id
     */
    public static function gbm_delete_user($user_id)
    {
        self::log_info('gbm_delete_user: ' . $user_id);
        unset(self::$options['users'][$user_id]);
    }

    /**
     * Triggered after the User gets delete from the database
     * @param $user_id
     */
    public static function gbm_deleted_user($user_id)
    {
        self::log_info('gbm_deleted_user: ' . $user_id);
        unset(self::$options['users'][$user_id]);
    }

    /**
     * User deleted from Network Site installs trigger this hook
     * @param $user_id
     */
    public static function gbm_wpmu_delete_user($user_id)
    {
        self::log_info('gbm_wpmu_delete_user: ' . $user_id);
        // TODO: test multi site network user delete
        //unset(self::$options['users'][$user_id]);
    }

    ////////////////////////////////////////
    // User List
    ////////////////////////////////////////

    /**
     * @param $columns
     * @return mixed
     */
    public static function gbm_add_user_columns($columns)
    {
        $columns['gbm_hash'] = 'GrantedByMe';
        return $columns;
    }

    /**
     * @param $value
     * @param $column_name
     * @param $user_id
     * @return mixed
     */
    public static function gbm_show_user_id_column_content($value, $column_name, $user_id)
    {
        $user = get_userdata($user_id);
        if ('gbm_hash' == $column_name && isset(self::$options['users'][$user->ID]))
            return 'Connected';
        return $value;
    }

    ////////////////////////////////////////
    // Common
    ////////////////////////////////////////

    /**
     * Called in loaded phase
     */
    public static function gbm_init()
    {
        //self::log_info('gbm_init');
    }

    /**
     * Called in loaded phase
     */
    public static function gbm_loaded()
    {
        //self::log_info('gbm_loaded');
    }

    ////////////////////////////////////////
    // Comment
    ////////////////////////////////////////

    /**
     * Called when a comment form page is rendered
     */
    public static function gbm_comment_form()
    {
        self::log_info('gbm_comment_form');
        wp_nonce_field('csrf-token', '_token');
        self::gbm_widget_show();
    }

    /**
     * @param $commentdata
     * @return mixed
     */
    public static function gbm_comment_validate($commentdata)
    {
        self::log_info('gbm_comment_validate: ' . current_filter());
        if (!is_user_logged_in()) {
            if (!isset($_POST['GrantedByMe-token'])) {
                wp_die('no GrantedByMe token set!');
            } elseif (empty($_POST['GrantedByMe-token'])) {
                wp_die('GrantedByMe token empty!');
            } else {
                $challenge = $_POST['GrantedByMe-token'];
                if (!self::gbm_is_granted($challenge)) {
                    wp_die('Unauthorized GrantedByMe session.');
                    $_POST['GrantedByMe-token'] = '';
                }
            }
        }
        return $commentdata;
    }

    ////////////////////////////////////////
    // Login
    ////////////////////////////////////////

    /**
     * Called when the login form is rendered
     */
    public static function gbm_login_form()
    {
        self::log_info('gbm_login_form');
        wp_nonce_field('csrf-token', '_token');
        self::gbm_widget_show();
    }

    /**
     * @param $user
     * @param bool|false $password
     * @return WP_Error
     */
    public static function gbm_login_validate($user, $password = false)
    {
        self::log_info('gbm_login_validate: ' . current_filter());
        self::log_info('user: ' . $user->ID);
        //self::log_info('pwd: ' . $password);
        if ($user && self::$options['auth_mode'] == \GBM\ApiRequest::$MODE_SFA_GBM) {
            if (!isset($_POST['GrantedByMe-token'])) {
                remove_action('authenticate', 'wp_authenticate_username_password', 20);
                $user = new WP_Error('denied', __('<strong>ERROR</strong>: no GrantedByMe token set!'));
            } elseif (empty($_POST['GrantedByMe-token'])) {
                remove_action('authenticate', 'wp_authenticate_username_password', 20);
                $user = new WP_Error('denied', __('<strong>ERROR</strong>: GrantedByMe token empty!'));
            } else {
                $token = $_POST['GrantedByMe-token'];
                if (!self::gbm_is_granted($token)) {
                    remove_action('authenticate', 'wp_authenticate_username_password', 20);
                    $user = new WP_Error('denied', __('<strong>ERROR</strong>: Unauthorized GrantedByMe session.'));
                    $_POST['GrantedByMe-token'] = '';
                }
            }
        }
        return $user;
    }

    /**
     * TBD
     */
    public static function gbm_logout()
    {
        self::log_info('gbm_logout');
        if(isset($_SESSION['gbm_challenge'])) {
            self::log_info('Logging out GBM user.');
            try {
                $response = self::$gbm->revokeChallenge($_SESSION['gbm_challenge']);
            } catch (Exception $e) {
                self::log_info('RevokeChallenge exception');
            }
            unset($_SESSION['gbm_challenge']);
        }
    }

    ////////////////////////////////////////
    // Register
    ////////////////////////////////////////

    /**
     * Called when the register form is rendered
     */
    public static function gbm_register_form()
    {
        self::log_info('gbm_register_form');
        wp_nonce_field('csrf-token', '_token');
        if(isset($_SESSION["gbm_form_error_message"])) {
            ?>
            <div id="login_error"><strong>ERROR: </strong> <?php echo $_SESSION["gbm_form_error_message"]; ?></div>
            <?php
            unset($_SESSION["gbm_form_error_message"]);
        } else if(isset($_SESSION['gbm_registration_completed'])) {
            unset($_SESSION['gbm_registration_completed']);
            wp_redirect( home_url() );
            exit;
        }
        self::gbm_widget_show();
    }

    /**
     * @param $errors
     * @param bool|false $sanitized_user_login
     * @param bool|false $user_email
     * @return mixed
     */
    public static function gbm_register_validate($errors, $sanitized_user_login = false, $user_email = false)
    {
        self::log_info('gbm_register_validate: ' . current_filter());
        self::log_info('sanitized_user_login: ' . $sanitized_user_login);
        self::log_info('user_email: ' . $user_email);
        return $errors;
    }

    /**
     * @param $user_id
     */
    public static function gbm_user_register($user_id)
    {
        self::log_info('gbm_user_register: ' . current_filter());
        self::log_info('user_id: ' . $user_id);
        //wp_safe_redirect(site_url() . '/wp-login.php?action=gbm_register');
        //exit;
    }

    ////////////////////////////////////////
    // Widget
    ////////////////////////////////////////

    /**
     * Widget show helper
     */
    public static function gbm_widget_show()
    {
        self::log_info('gbm_widget_show: ' . current_action());
        self::gbm_localize_script();
        if (!is_user_logged_in()) {
            the_widget('GrantedByMeWidget');
        }
    }

    /**
     * Widget renderer
     *
     * @param $atts
     * @return string
     */
    public static function gbm_widget_render($atts)
    {
        self::log_info('gbm_widget_render: ' . current_action());

        global $wp_widget_factory;
        $name = $class = $instance = $id = '';

        extract(shortcode_atts(array(
            'name' => 'GrantedByMeWidget'
        ), $atts));

        $widget_name = wp_specialchars($name);

        if (!is_a($wp_widget_factory->widgets[$widget_name], 'WP_Widget')):
            $wp_class = 'WP_Widget_' . ucwords(strtolower($class));

            if (!is_a($wp_widget_factory->widgets[$wp_class], 'WP_Widget')):
                return '<p>' . sprintf(__("%s: Widget class not found. Make sure this widget exists and the class name is correct"), '<strong>' . $class . '</strong>') . '</p>';
            else:
                $class = $wp_class;
            endif;
        endif;

        ob_start();
        the_widget($widget_name, $instance, array(
            'widget_id' => 'arbitrary-instance-' . $id,
            'before_widget' => '',
            'after_widget' => '',
            'before_title' => '',
            'after_title' => ''
        ));
        $output = ob_get_contents();
        ob_end_clean();

        return $output;

    }

    /**
     * @param $challenge
     * @return bool
     */
    private static function gbm_is_granted($challenge)
    {
        $isGranted = false;
        try {
            $response = self::$gbm->getChallengeState($challenge);
            if ($response['status'] == \GBM\ApiRequest::$STATUS_VALIDATED) {
                $isGranted = true;
            }
        } catch (Exception $e) {
            self::log_info('getChallengeState exception');
        }
        return $isGranted;
    }

    /**
     * Asset loader
     */
    public static function gbm_enqueue_asset()
    {
        //self::log_info('gbm_enqueue_asset: ' . current_action());
        self::gbm_check_session();
        print '<meta name="csrf-token" content="' . wp_create_nonce('csrf-token') . '">';
        self::gbm_enqueue_style();
        self::gbm_enqueue_script();
    }

    /**
     * Validate GBM auth. session
     */
    public static function gbm_check_session()
    {
        //self::log_info('gbm_check_session: ' . current_action());
        if(isset($_SESSION['gbm_challenge'])
            && !self::gbm_is_granted($_SESSION['gbm_challenge'])) {
            self::log_info('GBM Session is expired, logging out user.');
            unset($_SESSION['gbm_challenge']);
            wp_logout();
            wp_redirect( home_url() );
            exit;
        }
    }

    /**
     * Asset loader
     */
    public static function gbm_enqueue_style()
    {
        wp_enqueue_style(
            'grantedbyme-modal-css',
            'https://cdn.grantedby.me/components/modal/css/grantedbyme.css'
        );
    }

    /**
     * Asset loader
     */
    public static function gbm_enqueue_script()
    {
        wp_enqueue_script(
            'grantedbyme-qr',
            'https://cdnjs.cloudflare.com/ajax/libs/lrsjng.jquery-qrcode/0.12.0/jquery.qrcode.min.js',
            array('jquery'),
            null,
            true
        );
        wp_enqueue_script(
            'grantedbyme',
            'https://cdn.grantedby.me/components/modal/js/grantedbyme.js',
            array('jquery', 'grantedbyme-qr'),
            null,
            true
        );
    }

    /**
     * Asset localize used to configure front end
     */
    public static function gbm_localize_script()
    {
        self::log_info('gbm_localize_script: ' . current_action());
        $callback_type = 'reload';
        $redirect_url = '/';
        $challengeType = 'authenticate';
        if (current_action() == 'login_form') {
            $callback_type = 'redirect';
            $redirect_url = home_url();
            $challengeType = 'authenticate';
        } else if (current_action() == 'register_form') {
            // get_option('users_can_register') == 1
            $callback_type = 'reload';
            //$redirect_url = get_home_url();
            $challengeType = 'profile';
        } else if (is_user_logged_in()) {
            $callback_type = 'post';
            $challengeType = 'authorize';
        } else {
            self::log_info('Illegal operation error');
        }
        $challenge = isset($_POST['GrantedByMe-token']) ? $_POST['GrantedByMe-token'] : '';
        $ajax_url = wp_make_link_relative(plugins_url('grantedbyme.ajax.php', __FILE__));
        wp_localize_script('grantedbyme', 'pluginURLs', array(
            'ajaxURL' => $ajax_url,
            'callbackType' => $callback_type,
            'redirectURL' => $redirect_url,
            'challenge' => $challenge,
            'challengeType' => $challengeType
        ));
    }

}
