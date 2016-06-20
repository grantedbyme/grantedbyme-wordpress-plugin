<?php

/*
Plugin Name: GrantedBy.Me
Plugin URI: https://grantedby.me
Description: The plugin provides password-free authentication with the GrantedBy.Me mobile app.
Version: 1.0.7
Author: GrantedBy.Me Ltd.
Author URI: https://grantedby.me
License: MIT
*/

// Make sure we don't expose any info if called directly
if (!function_exists('add_action')) {
    echo 'Hi there!  I\'m just a plugin, not much I can do when called directly.';
    exit;
}

// Constants
define('GBM_VERSION', '1.0.7');
define('GBM_MINIMUM_WP_VERSION', '3.2');
define('GBM_PLUGIN_URL', plugin_dir_url(__FILE__));
define('GBM_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('GBM_WIDGET_NAME', 'GrantedByMeWidget');

// Auto update plugin
if (is_admin()) {
    require_once 'vendor/yahnis-elsts/plugin-update-checker/plugin-update-checker.php';
    $myUpdateChecker = PucFactory::buildUpdateChecker(
        'https://cdn.grantedby.me/plugins/wordpress/grantedbyme.json',
        __FILE__
    );
}

// Create log data folder if not exists
@mkdir(GBM_PLUGIN_DIR . 'data', 0777);

// Register plugin activation hooks
register_activation_hook(__FILE__, array('GrantedByMeWP', 'gbm_plugin_activation'));
register_deactivation_hook(__FILE__, array('GrantedByMeWP', 'gbm_plugin_deactivation'));

// Composer auto loader
require_once(GBM_PLUGIN_DIR . 'vendor/autoload.php');
require_once(GBM_PLUGIN_DIR . 'grantedbyme.options.php');
require_once(GBM_PLUGIN_DIR . 'grantedbyme.main.php');
require_once(GBM_PLUGIN_DIR . 'grantedbyme.widget.php');

// frontend
add_action('init', array('GrantedByMeWP', 'init'));

// admin
if (is_admin()) {
    require_once(GBM_PLUGIN_DIR . 'grantedbyme.settings.php');
    add_action('init', array('GrantedByMeSettingsPage', 'init'));
}

