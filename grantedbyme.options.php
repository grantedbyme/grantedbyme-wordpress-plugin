<?php

/**
 * GrantedByMe WordPress Options helper
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
class GrantedByMeOptions
{
    /**
     * Constructor
     */
    function __construct()
    {
    }

    /**
     * @return bool
     */
    public static function gbm_is_current_account_linked()
    {
        $options = get_option('grantedbyme_option_name');
        $current_user_id = get_current_user_id();
        if ($current_user_id == 0) {
            return false;
        }
        if(!isset($options['users']) || !isset($options['users'][$current_user_id])) {
            return false;
        }
        $authenticator_secret = $options['users'][$current_user_id];
        return isset($authenticator_secret) && !empty($authenticator_secret) && strlen($authenticator_secret) >= 128;
    }
}
