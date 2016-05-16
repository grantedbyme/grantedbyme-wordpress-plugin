<?php

/**
 * GrantedByMe WordPress Widget
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
class GrantedByMeWidget extends WP_Widget
{
    function __construct()
    {
        parent::__construct(
            'GrantedByMeWidget',
            __('GrantedByMeWidget', 'GrantedByMeWidget_domain'),
            array('description' => __('GrantedByMeWidget', 'GrantedByMeWidget_domain'))
        );
    }

    public function widget($args, $instance)
    {
        echo $args['before_widget'];
        echo '<!--GrantedByMe Component Start-->
        <div id="GrantedByMe-Container"></div>
        <div id="GrantedByMe-modal" class="GrantedByMe-modal"><div id="GrantedByMe-content"></div></div>
        <!--GrantedByMe Component End-->';
        echo $args['after_widget'];
    }
}

function registerGrantedByMeWidget()
{
    register_widget('GrantedByMeWidget');
}

add_action('widgets_init', 'registerGrantedByMeWidget');
