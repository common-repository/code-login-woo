<?php
if ( ! defined( 'ABSPATH' ) ) {
    exit; // Exit if accessed directly.
}

do_action( 'woocommerce_before_customer_login_form' ); ?>


<h2><?php esc_html_e( 'Login with Code', 'woocommerce' ); ?></h2>

<form class="woocommerce-form woocommerce-form-login login" method="post">
    <p class="woocommerce-form-row woocommerce-form-row--wide form-row form-row-wide">
        <label for="code"><?php esc_html_e( 'Code', 'woocommerce' ); ?>&nbsp;<span class="required">*</span></label>
        <input type="text" class="woocommerce-Input woocommerce-Input--text input-text" name="code" id="code" />
    </p>

    <p class="form-row">
        <?php wp_nonce_field( 'code-login-woo', 'code-login-woo-nonce' ); ?>
        <button type="submit" class="woocommerce-button button woocommerce-form-login__submit" name="login" value="<?php esc_attr_e( 'Log in', 'woocommerce' ); ?>"><?php esc_html_e( 'Log in', 'woocommerce' ); ?></button>
    </p>
</form>