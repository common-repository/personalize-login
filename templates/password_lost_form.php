<div id="password-lost-form" class="widecolumn">
	<?php if (isset($attributes['show_title'])) : ?>
		<h3><?php esc_html_e('Forgot Your Password?', 'personalize-login'); ?></h3>
	<?php endif; ?>

	<?php if (isset($attributes['lost_password_sent'])) : ?>
		<p class="login-info">
			<?php esc_html_e('Check your email for a link to reset your password.', 'personalize-login'); ?>
		</p>
	<?php endif; ?>

	<?php if (count($attributes['errors']) > 0) : ?>
		<?php foreach ($attributes['errors'] as $error) : ?>
			<p>
				<?php echo $error; ?>
			</p>
		<?php endforeach; ?>
	<?php endif; ?>

	<p>
		<?php
		esc_html_e(
			"Enter your email address and we'll send you a link you can use to pick a new password.",
			'personalize-login'
		);
		?>
	</p>

	<form id="lostpasswordform" action="<?php echo wp_lostpassword_url(); ?>" method="post">
		<p class="form-row">
			<label for="user_login"><?php esc_html_e('Email', 'personalize-login'); ?>
				<input type="text" name="user_login" id="user_login">
		</p>

		<p class="lostpassword-submit">
			<input type="submit" name="submit" class="lostpassword-button" value="<?php esc_html_e('Reset Password', 'personalize-login'); ?>" />
		</p>
	</form>
</div>
