<?php
/**
 * Plugin Name: Code Login for WooCommerce
 * Plugin URI:  https://wordpress.org/plugins/code-login-woo
 * Description: Increase Customer lifetime value by allowing secure, password-less, email code registration and login for your WooCommerce customers.
 * Version:     1.0.0
 * Author:      Handcraft Byte
 * Author URI:  https://handcraftbyte.com/
 * License:     GPLv2 or later
 * License URI: http://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: code-login-woo
 * Domain Path: /languages
 *
 * WC requires at least: 4.0
 * WC tested up to: 6.7.0
 */

/**
 * Replace the default customer login form with code login form
 * Removes password field and adds code step
 */
add_filter('woocommerce_locate_template', function($template, $template_name, $template_path) {
   if ('myaccount/form-login.php' === $template_name && isset($_GET['code-sent'])) {
      return trailingslashit(plugin_dir_path( __FILE__ )) . 'templates/myaccount/form-login-code.php';
   }
   return $template;
}, 10, 4);


add_action( 'woocommerce_login_form', function() {
    ?>
    <p class="form-row">
        <?php wp_nonce_field( 'code-login-woo', 'code-login-woo-nonce' ); ?>
        <button type="submit" class="woocommerce-button button woocommerce-form-login__submit" name="login" value="<?php esc_attr_e( 'Log in', 'woocommerce' ); ?>"><?php esc_html_e( 'Get Login Code', 'woocommerce' ); ?></button>
    </p>
    <?php
});

/**
 * Detect code login attempt, instead of default logic, generate code and send it out
 */
add_action( 'wp_loaded', function() {
    global $wpdb;
    $logger = wc_get_logger();
    $nonce_value = wc_get_var( $_REQUEST['woocommerce-login-nonce'], wc_get_var( $_REQUEST['_wpnonce'], '' ) );

    if ( isset( $_POST['login'], $_POST['username'] ) && wp_verify_nonce( $nonce_value, 'woocommerce-login' ) ) {

        $email = sanitize_email($_POST['username']);
        $rememberme = isset($_POST['rememberme']) ? sanitize_key($_POST['rememberme']) : "";
        $redirecturl = sanitize_url($_POST['_wp_http_referer']);
        $user = get_user_by('email', $email);
        $code = rand(100000, 999999);

        wp_mail( $email, 'Login code', "Hello,\nhere is the code to login:\n" . esc_html($code) . "\n" );

        if (false !== $user) {
            $wpdb->insert($wpdb->prefix . "code_login_woo", [
                'time' => date('Y-m-d H:i:s'),
                'code_hash' => sha1($code),
                'user_id' => $user->ID,
                'remember_me' => $rememberme,
                'redirect_url' => $redirecturl
            ]);
        }
            
        wp_safe_redirect( add_query_arg( 'code-sent', 'true', wc_get_account_endpoint_url( 'login' ) ) );
            exit;
    }
}, 20 );

/**
 * Internal authentication filter that detects code login and search for it in codes table.
 */
add_filter('authenticate', function($existingUser, $username, $password) {
    global $code_login_attempt, $wpdb;
    $code = $wpdb->get_row( $wpdb->prepare(
        "SELECT * FROM {$wpdb->prefix}code_login_woo WHERE code_hash = %s AND time >= NOW() - INTERVAL 10 MINUTE", $password
    ) );

    if (true === $code_login_attempt && 'code' === $username && false !== $code) { // AND CODE
        return new WP_User($code->user_id);
    }
    return $existingUser;
}, 10, 3);

/**
 * Detect login code from customised fields being provided and perform the login logic using the code
 */
add_action( 'wp_loaded', function() {
    global $code_login_attempt, $wpdb;
    $nonce_value = wc_get_var( $_REQUEST['code-login-woo-nonce'], wc_get_var( $_REQUEST['_wpnonce'], '' ) );

    if ( isset( $_POST['code'] ) && wp_verify_nonce( $nonce_value, 'code-login-woo' ) ) {

        $code_hash = sha1(sanitize_key($_POST['code']));

        $code = $wpdb->get_row( $wpdb->prepare(
            "SELECT * FROM {$wpdb->prefix}code_login_woo WHERE code_hash = %s AND time >= NOW() - INTERVAL 10 MINUTE", $code_hash
        ) );

        if (null === $code) {
            return new WP_Error( 'broke', __( "I've fallen and can't get up", "my_textdomain" ) );
        }

        // modified credentials
        $creds = [
            'user_login' => 'code',
            'user_password' => $code_hash,
            'remember' => $code->remember_me,
        ];
        $code_login_attempt = true;
        $user = wp_signon( apply_filters( 'woocommerce_login_credentials', $creds ), is_ssl() );

        if ( is_wp_error( $user ) ) {
            throw new Exception( $user->get_error_message() );
        } else {

            if ( ! empty( $code->redirect_url ) ) {
                $redirect = wp_unslash( $code->redirect_url );
            } elseif ( wc_get_raw_referer() ) {
                $redirect = wc_get_raw_referer();
            } else {
                $redirect = wc_get_page_permalink( 'myaccount' );
            }

            wp_redirect( wp_validate_redirect( apply_filters( 'woocommerce_login_redirect', remove_query_arg( 'wc_error', $redirect ), $user ), wc_get_page_permalink( 'myaccount' ) ) );
            exit;
        }
    }
}, 20 );


/**
 * Database initialisation
 */
register_activation_hook( __FILE__, function () {
   global $wpdb;

   $table_name = $wpdb->prefix . "code_login_woo";

   $charset_collate = $wpdb->get_charset_collate();

   $sql = "CREATE TABLE $table_name (
     id mediumint(9) NOT NULL AUTO_INCREMENT,
     time datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
     code_hash text NOT NULL,
     user_email_hash text NOT NULL,
     remember_me text NOT NULL,
     redirect_url varchar(55) DEFAULT '' NOT NULL,
     PRIMARY KEY  (id)
   ) $charset_collate;";

   require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
   dbDelta( $sql );

   add_option( 'code_login_woo_db_version', '1.0.0' );
});
