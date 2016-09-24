<?php

use Monolog\Logger;
use Monolog\Handler\StreamHandler;

/**
 * GrantedByMe WordPress Plug-In Admin
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
class GrantedByMeSettingsPage
{
    /**
     * GrantedByMe Options
     */
    private $options;
    /**
     * GrantedByMe SDK
     */
    private $gbm;
    /**
     * Monolog logger
     */
    private $log;
    /**
     * Static singleton
     */
    private static $instance;

    /**
     * Singleton start up
     */
    public static function init()
    {
        self::$instance = new GrantedByMeSettingsPage();
    }

    /**
     * Instance start up
     */
    public function __construct()
    {
        // get reference to plugin settings array
        $this->options = get_option('grantedbyme_option_name');
        // initialize logger
        $this->log = new Logger('GrantedByMeWPAdmin');
        $this->log->pushHandler(new StreamHandler(GBM_PLUGIN_DIR . 'data/app.log', Logger::INFO));
        // initialize gbm sdk
        $this->gbm = GrantedByMeWP::gbm_get_sdk();
        // setup wp admin hooks
        add_action('admin_menu', array($this, 'gbm_admin_menu'));
        add_action('admin_init', array($this, 'gbm_admin_init'));
        add_action('admin_post_update', array($this, 'gbm_admin_post_update'));
        // extension for /wp-admin/admin-ajax.php
        // add_action('wp_ajax_ajax_action', array($this, 'gbm_ajax_admin'));
        // add_action('wp_ajax_nopriv_ajax_action', array($this, 'gbm_ajax_nopriv'));
    }

    /**
     * Admin AJAX handler
     */
    /*public function gbm_ajax_admin()
    {
        $this->log->addInfo('gbm_ajax_admin', $_POST);
    }*/

    /**
     * Non Admin AJAX handler
     */
    /*public function gbm_ajax_nopriv()
    {
        $this->log->addInfo('gbm_ajax_nopriv', $_POST);
    }*/

    /**
     * Add menu hook
     */
    public function gbm_admin_menu()
    {
        add_menu_page('Settings', 'GrantedByMe', 'read', 'grantedbyme-home', array($this, 'create_admin_page'));
        if ($this->gbm->isActivated()) {
            if (!GrantedByMeOptions::gbm_is_current_account_linked()) {
                add_submenu_page('grantedbyme-home', 'Account', 'Account', 'read', 'grantedbyme-account', array($this, 'create_account_page'));
            }
            add_submenu_page('grantedbyme-home', 'Deactivation', 'Deactivate', 'edit_plugins', 'grantedbyme-deactivation', array($this, 'create_deactivation_page'));
        } else {
            add_submenu_page('grantedbyme-home', 'Activation', 'Activate', 'edit_plugins', 'grantedbyme-activation', array($this, 'create_activation_page'));
        }
        //add_submenu_page('grantedbyme-home', 'Preferences', 'Preferences', 'edit_plugins', 'grantedbyme-preferences', array($this, 'create_preferences_page'));
    }

    /**
     * Admin init hook
     */
    public function gbm_admin_init()
    {
        if ($this->gbm->isActivated()) {
            $this->gbm_admin_deactivation_init();
        } else {
            $this->gbm_admin_activation_init();
        }
        $this->gbm_admin_preferences_init();
        $this->gbm_admin_account_init();
    }

    /**
     * Options page callback
     */
    public function create_admin_page()
    {
        ?>
        <div class='wrap'>
            <h2>GrantedByMe Settings</h2>
        </div>
        <?php
    }

    /**
     * Options sanitizer
     *
     * @param $input
     * @return array
     */
    public function gbm_admin_sanitize($input)
    {
        $this->log->addInfo('gbm_admin_sanitize');
        $new_input = array();
        // GBM Service key
        if (isset($input['service_key'])) {
            $new_input['service_key'] = sanitize_text_field($input['service_key']);
        }
        // Service private key
        if (isset($input['private_key'])) {
            $new_input['private_key'] = $input['private_key'];
        }
        // Service public key
        if (isset($input['public_key'])) {
            $new_input['public_key'] = $input['public_key'];
        }
        // Server public key
        if (isset($input['server_key'])) {
            $new_input['server_key'] = $input['server_key'];
        }
        // Authenticator secret list by user id keys
        if (isset($input['users'])) {
            $new_input['users'] = $input['users'];
            // TODO: iterate over values and sanitize them as SHA-512 strings
        }
        // API URL
        if (isset($input['api_url'])) {
            $new_input['api_url'] = sanitize_text_field($input['api_url']);
        }
        // Authenticate mode
        if (isset($input['auth_mode'])) {
            $new_input['auth_mode'] = intval($input['auth_mode']);
            if ($new_input['auth_mode'] < 1 || $new_input['auth_mode'] > 4) {
                $new_input['auth_mode'] = \GBM\ApiRequest::$MODE_2FA_OPT;
            }
        }
        // Return sanitized result
        return $new_input;
    }

    /**
     * Common POST form handler
     */
    public function gbm_admin_post_update()
    {
        $this->log->addInfo('gbm_admin_post_update', $_POST);
        if(isset($_POST['form_action'])) {
            if($_REQUEST['form_action'] == 'activation') {
                $this->gbm_admin_post_activation();
            } else if($_REQUEST['form_action'] == 'deactivation') {
                $this->gbm_admin_post_deactivation();
            } else if($_REQUEST['form_action'] == 'account') {
                $this->gbm_admin_post_account();
            } else if($_REQUEST['form_action'] == 'preferences') {
                $this->gbm_admin_post_preferences();
            }
            wp_redirect(site_url() . '/wp-admin/admin.php?page=grantedbyme-' . $_REQUEST['form_action']);
            exit;
        }
    }

    ////////////////////////////////////////
    // ACTIVATE
    ////////////////////////////////////////

    public function gbm_admin_post_activation()
    {
        $this->log->addInfo('gbm_admin_post_activation');
        if (isset($_POST['_token'])) {
            if (!wp_verify_nonce($_POST['_token'], 'csrf-token')) {
                $_SESSION['gbm_form_error'] = 'csrf_error';
            } else {
                $service_key = trim($_POST['grantedbyme_option_name']['service_key']);
                if (!isset($service_key) || empty($service_key) || strlen($service_key) < 128 || strlen($service_key) > 255) {
                    $_SESSION['gbm_form_error'] = 'service_key_error';
                } else {
                    try {
                        $api_result = $this->gbm->activateService($service_key);
                        if (isset($api_result) && is_array($api_result)) {
                            $this->log->addInfo('API result', $api_result);
                        }
                    } catch (Exception $e) {
                        $this->log->addInfo('Caught exception: ' . $e->getMessage());
                        $_SESSION['gbm_form_error'] = 'api_exception';
                    }
                    if (isset($api_result) && isset($api_result['success']) && $api_result['success'] == true) {
                        $this->options['service_key'] = $service_key;
                        $this->options['private_key'] = $api_result['private_key'];
                        $this->options['public_key'] = $api_result['public_key'];
                        $this->options['server_key'] = $api_result['server_key'];
                        if (!isset($this->options['api_url'])) {
                            $this->options['api_url'] = $this->gbm->getApiUrl();
                        }
                        $current_user_id = get_current_user_id();
                        // TODO: check for user_id == 0 and handle the error
                        $is_saved = update_option('grantedbyme_option_name', $this->options);
                        $this->log->addInfo('GrantedByMe service activated');
                        wp_redirect(site_url() . '/wp-admin/admin.php?page=grantedbyme-account');
                        exit;
                    } else {
                        $_SESSION['gbm_form_error'] = 'api_error';
                    }
                }
            }
        }
    }

    /**
     * Options page callback
     */
    public function create_activation_page()
    {
        $this->log->addInfo('create_activation_page');
        $form_errors = new WP_Error();
        if (isset($_SESSION['gbm_form_error'])) {
            $form_error = $_SESSION['gbm_form_error'];
            if($form_error == 'csrf_error') {
                $form_errors->add($form_error, __('General error'));
                add_settings_error(
                    $form_error, esc_attr($form_error), $form_errors->get_error_message($form_error), $form_error
                );
            } else if($form_error == 'service_key_error') {
                $form_errors->add($form_error, __('Invalid service key'));
                add_settings_error(
                    $form_error, esc_attr($form_error), $form_errors->get_error_message($form_error), $form_error
                );
            } else if($form_error == 'api_exception') {
                $form_errors->add($form_error, __('Service key error'));
                add_settings_error(
                    $form_error, esc_attr($form_error), $form_errors->get_error_message($form_error), $form_error
                );
            } else if($form_error == 'api_error') {
                $form_errors->add($form_error, __('Invalid or already activated service key'));
                add_settings_error(
                    $form_error, esc_attr($form_error), $form_errors->get_error_message($form_error), $form_error
                );
            } else {
                $this->log->addInfo('unhandled error: ' . $form_error);
            }
            unset($_SESSION['gbm_form_error_code']);
            unset($_SESSION['gbm_form_error_message']);
            unset($_SESSION['gbm_form_error']);
        }
        // error handler end
        ?>
        <div class='wrap'>
            <h2>GrantedByMe Activation</h2>

            <form method='post' action='<?php echo site_url() . '/wp-admin/admin-post.php' ?>'>
                <?php wp_nonce_field('csrf-token', '_token'); ?>
                <input type='hidden' name='form_action' value='activation'/>
                <?php
                // This prints out all hidden setting fields
                settings_fields('grantedbyme_option_group');
                do_settings_sections('grantedbyme-activation');
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }

    /**
     * TBD
     */
    public function gbm_admin_activation_init()
    {
        register_setting(
            'grantedbyme_option_group', // Option group
            'grantedbyme_option_name', // Option name
            array($this, 'gbm_admin_sanitize') // Sanitize
        );
        add_settings_section(
            'setting_section_id', // ID
            'Activation Settings', // Title
            array($this, 'gbm_admin_activation_info'), // Callback
            'grantedbyme-activation' // Page
        );
        add_settings_field(
            'service_key',
            'Service key',
            array($this, 'gbm_service_key_callback'),
            'grantedbyme-activation',
            'setting_section_id'
        );
    }

    /**
     * TBD
     */
    public function gbm_admin_activation_info()
    {
        settings_errors();
        echo 'Please enter your activation information:';
    }

    /**
     * TBD
     */
    public function gbm_service_key_callback()
    {
        printf(
            '<textarea rows="3" cols="40" id="service_key" name="grantedbyme_option_name[service_key]">%s</textarea>',
            isset($this->options['service_key']) ? esc_attr($this->options['service_key']) : ''
        );
    }

    ////////////////////////////////////////
    // DEACTIVATE
    ////////////////////////////////////////

    public function gbm_admin_post_deactivation()
    {
        $this->log->addInfo('gbm_admin_post_deactivation');
        if (isset($_POST['_token'])) {
            if (!wp_verify_nonce($_POST['_token'], 'csrf-token')) {
                $_SESSION['gbm_form_error'] = 'csrf_error';
            } else {
                $service_key = trim($_POST['grantedbyme_option_name']['service_key']);
                if (!isset($service_key) /*|| $service_key != $this->options['service_key']*/) {
                    $_SESSION['gbm_form_error'] = 'service_key_error';
                } else {
                    $this->options = array();
                    $is_saved = update_option('grantedbyme_option_name', $this->options);
                    $this->log->addInfo('GrantedByMe service deactivated');
                    wp_redirect(site_url() . '/wp-admin/admin.php?page=grantedbyme-activation');
                    exit;
                }
            }
        }
    }

    /**
     * Options page callback
     */
    public function create_deactivation_page()
    {
        $this->log->addInfo('create_deactivation_page');
        $form_errors = new WP_Error();
        if (isset($_SESSION['gbm_form_error'])) {
            $form_error = $_SESSION['gbm_form_error'];
            if($form_error == 'csrf_error') {
                $form_errors->add($form_error, __('General error'));
                add_settings_error(
                    $form_error, esc_attr($form_error), $form_errors->get_error_message($form_error), $form_error
                );
            } else if($form_error == 'service_key_error') {
                $form_errors->add($form_error, __('Invalid service key'));
                add_settings_error(
                    $form_error, esc_attr($form_error), $form_errors->get_error_message($form_error), $form_error
                );
            } else {
                $this->log->addInfo('unhandled error: ' . $form_error);
            }
            unset($_SESSION['gbm_form_error_code']);
            unset($_SESSION['gbm_form_error_message']);
            unset($_SESSION['gbm_form_error']);
        }
        ?>
        <div class='wrap'>
            <h2>GrantedByMe Deactivation</h2>

            <form method='post' action='<?php echo site_url() . '/wp-admin/admin-post.php' ?>'>
                <?php wp_nonce_field('csrf-token', '_token'); ?>
                <input type='hidden' name='form_action' value='deactivation'/>
                <?php
                // This prints out all hidden setting fields
                settings_fields('grantedbyme_option_group');
                do_settings_sections('grantedbyme-deactivation');
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }

    /**
     * TBD
     */
    public function gbm_admin_deactivation_init()
    {
        register_setting(
            'grantedbyme_option_group', // Option group
            'grantedbyme_option_name', // Option name
            array($this, 'gbm_admin_sanitize') // Sanitize
        );
        add_settings_section(
            'setting_section_id', // ID
            'Deactivation Settings', // Title
            array($this, 'gbm_admin_deactivation_info'), // Callback
            'grantedbyme-deactivation' // Page
        );
        add_settings_field(
            'service_key',
            'Service key',
            array($this, 'gbm_service_key_callback'),
            'grantedbyme-deactivation',
            'setting_section_id'
        );
    }

    /**
     * TBD
     */
    public function gbm_admin_deactivation_info()
    {
        settings_errors();
        echo 'Please confirm your deactivation:';
    }


    ////////////////////////////////////////
    // ACCOUNT
    ////////////////////////////////////////

    public function gbm_admin_post_account()
    {
        $this->log->addInfo('gbm_admin_post_account');
        if (isset($_POST['_token'])) {
            if (!wp_verify_nonce($_POST['_token'], 'csrf-token')) {
                $_SESSION['gbm_form_error'] = 'csrf_error';
            } else {
                wp_redirect(site_url() . '/wp-admin/admin.php?page=grantedbyme-home');
                exit;
            }
        }
    }

    /**
     * TBD
     */
    public function gbm_admin_account_init()
    {
        register_setting(
            'grantedbyme_option_group', // Option group
            'grantedbyme_option_name', // Option name
            array($this, 'gbm_admin_sanitize') // Sanitize
        );

        add_settings_section(
            'setting_section_id', // ID
            'Account Linking', // Title
            array($this, 'gbm_admin_account_info'), // Callback
            'grantedbyme-account' // Page
        );
    }

    /**
     * TBD
     */
    public function create_account_page()
    {
        $this->log->addInfo('create_account_page');
        $form_errors = new WP_Error();
        if (isset($_SESSION['gbm_form_error'])) {
            $form_error = $_SESSION['gbm_form_error'];
            if($form_error == 'csrf_error') {
                $form_errors->add($form_error, __('General error'));
                add_settings_error(
                    $form_error, esc_attr($form_error), $form_errors->get_error_message($form_error), $form_error
                );
            } else if($form_error == 'api_error') {
                $form_errors->add($form_error, __('API error: ' . $_SESSION['gbm_form_error_code']));
                add_settings_error(
                    $form_error, esc_attr($form_error), $form_errors->get_error_message($form_error), $form_error
                );
            } else {
                $this->log->addInfo('unhandled error: ' . $form_error);
            }
            unset($_SESSION['gbm_form_error_code']);
            unset($_SESSION['gbm_form_error_message']);
            unset($_SESSION['gbm_form_error']);
        }
        ?>
        <h2>GrantedByMe Account</h2>
        <div class='wrap'>
            <form id="registerform" method='post' action='<?php echo site_url() . '/wp-admin/admin-post.php' ?>'>
                <?php wp_nonce_field('csrf-token', '_token'); ?>
                <input type='hidden' name='form_action' value='account'/>
                <?php
                // This prints out all hidden setting fields
                settings_fields('grantedbyme_option_group');
                do_settings_sections('grantedbyme-account');
                //submit_button();
                ?>
            </form>
        </div>
        <?php
        GrantedByMeWP::gbm_enqueue_asset();
        GrantedByMeWP::gbm_localize_script();
        the_widget(GBM_WIDGET_NAME);
    }

    /**
     * TBD
     */
    public function gbm_admin_account_info()
    {
        settings_errors();
        echo 'Please link your account using the GrantedByMe mobile application:';
    }

    ////////////////////////////////////////
    // PREFERENCES
    ////////////////////////////////////////

    public function gbm_admin_post_preferences()
    {
        $this->log->addInfo('gbm_admin_post_preferences');
        // TODO: implement
    }

    /**
     * TBD
     */
    public function gbm_admin_preferences_init()
    {
        register_setting(
            'grantedbyme_option_group', // Option group
            'grantedbyme_option_name', // Option name
            array($this, 'gbm_admin_sanitize') // Sanitize
        );

        add_settings_section(
            'setting_section_id', // ID
            'Preferences Settings', // Title
            array($this, 'gbm_admin_preferences_info'), // Callback
            'grantedbyme-preferences' // Page
        );

        add_settings_field(
            'auth_mode',
            'Authenticate mode',
            array($this, 'gbm_auth_mode_callback'),
            'grantedbyme-preferences',
            'setting_section_id'
        );

        add_settings_field(
            'api_url',
            'API URL',
            array($this, 'gbm_api_url_callback'),
            'grantedbyme-preferences',
            'setting_section_id'
        );
    }

    /**
     * TBD
     */
    public function create_preferences_page()
    {
        $this->log->addInfo('create_preferences_page');
        // Validate against CSRF
        if (isset($_POST['_token'])) {
            $form_errors = new WP_Error();
            $has_errors = false;
            // validate csrf-token
            if (!wp_verify_nonce($_POST['_token'], 'csrf-token')) {
                $has_errors = true;
                $form_errors->add('csrf_error', __('General error'));
                add_settings_error(
                    'csrf_error',
                    esc_attr('csrf_error'),
                    $form_errors->get_error_message('csrf_error'),
                    'csrf_error'
                );
            }
            if ($has_errors == false) {
                $form_errors->add('success', __('Settings saved!'));
                add_settings_error(
                    'success',
                    esc_attr('success'),
                    $form_errors->get_error_message('success'),
                    'success'
                );
                // get form data
                if (isset($_POST['grantedbyme_option_name']['auth_mode'])) {
                    $this->options['auth_mode'] = intval($_POST['grantedbyme_option_name']['auth_mode']);
                }
                if (isset($_POST['grantedbyme_option_name']['api_url'])) {
                    $this->options['api_url'] = trim($_POST['grantedbyme_option_name']['api_url']);
                }
                $is_saved = update_option('grantedbyme_option_name', $this->options);
            }
        }
        ?>
        <div class='wrap'>
            <h2>GrantedByMe Preferences</h2>

            <form method='post' action=''>
                <?php wp_nonce_field('csrf-token', '_token'); ?>
                <input type='hidden' name='form_action' value='preferences'/>
                <?php
                // This prints out all hidden setting fields
                settings_fields('grantedbyme_option_group');
                do_settings_sections('grantedbyme-preferences');
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }

    /**
     * TBD
     */
    public function gbm_admin_preferences_info()
    {
        settings_errors();
        echo 'Please enter your preferences:';
    }

    /**
     * TBD
     */
    public function gbm_api_url_callback()
    {
        $v = isset($this->options['api_url']) ? esc_attr($this->options['api_url']) : $this->gbm->getApiUrl();
        ?>
        <input disabled size='30' id='api_url' name='grantedbyme_option_name[api_url]' value='<?php echo $v; ?>'/>
        <?php
    }

    /**
     * TBD
     */
    public function gbm_auth_mode_callback()
    {
        $v = isset($this->options['auth_mode']) ? intval($this->options['auth_mode']) : \GBM\ApiRequest::$MODE_2FA_OPT;
        ?>
        <select id='auth_mode' name='grantedbyme_option_name[auth_mode]'>
            <option value='1'<?php if ($v == 1) echo ' selected'; ?>>Password only</option>
            <option value='2'<?php if ($v == 2) echo ' selected'; ?>>GrantedByMe only</option>
            <option value='3'<?php if ($v == 3) echo ' selected'; ?>>Password or GrantedByMe</option>
            <option value='4'<?php if ($v == 4) echo ' selected'; ?>>Password and GrantedByMe</option>
        </select>
        <?php
    }


}
