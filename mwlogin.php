<?php
/*
Plugin Name: Mediawiki Login for Hitchwiki
Plugin URI: http://hitchwiki.org/
Description: Logs users in by using MediaWiki user table. Helper functions for both WordPress and BuddyPress.
Requires at least: WordPress 3.5.1 / BuddyPress 1.7
Version: 2.1.1
Author: Mikael Korpela, Philipp Gruber
Author URI: https://github.com/Hitchwiki/Unified-login
License: GNU General Public License
Site Wide Only: true
Network: true
*/

/**
 * Wordpress login helper with MediaWiki
 * @package mediawiki-login
 */
 

class MWAuthPlugin {
	
	private $domain = "http://hitchwiki.org";
	private $wiki = "/en";
	
	
	function MWAuthPlugin() {


		// TODO: Autologin users already logged in MW to WP
		//add_filter('init', array(&$this, 'mediawiki_session'));
		//add_action('init', array(&$this, 'mediawiki_autologin'));
		
		// TODO: Autologout users from MW when logging out from WP
		//add_action('wp_logout', array(&$this, 'logout'));

		//add_action('login_head', array(&$this, 'add_login_css'));
		//add_action('login_footer', array(&$this, 'add_login_link'));
		//add_action('check_passwords', array(&$this, 'generate_password'), 10, 3);
		
		// Perform after auth
		#add_filter('authenticate', array(&$this, 'mw_authenticate'), 10, 3);

		// Perform before auth
		#add_filter('wp_authenticate_user', array(&$this, 'mw_authenticate'), 10,2);

		#add_filter('clean_url', 					array(&$this, 'esc_url'), 10, 3); // currently esc_url() doesn't handle spaces in urls at /wp-includes/formatting.php — but filter gets already cleaned url...

		add_action('init', 							array(&$this, 'fix_user_roles'));
		add_action('wp_authenticate', 				array(&$this, 'mw_authenticate'), 10, 2);
		add_action('wp_logout', 					array(&$this, 'mw_logout'));
		#add_action('wp_login_failed', 				array(&$this, 'hw_login_fail'));
		
		add_filter('gettext', 						array(&$this, 'adjust_gettext'));
		add_filter('register', 						array(&$this, 'register_link'));
		add_filter('show_password_fields', 			array(&$this, 'disable_function'));
		add_filter('allow_password_reset', 			array(&$this, 'disable_function'));
		add_filter('sanitize_user', 				array(&$this, 'mw_sanitize_username'), 10, 3);
		#add_filter('login_url', 					array(&$this, 'mw_login_url'));
		
		// BuddyPress filters
		add_filter('bp_core_validate_user_signup', 	array(&$this, 'acl_bp_core_validate_user_signup'));
		add_filter('bp_core_get_core_userdata', 	array(&$this, 'fix_user_encoding'));
		add_filter('bp_core_get_userlink', 			array(&$this, 'fix_string_encoding'));
		add_filter('bp_core_get_user_displayname', 	array(&$this, 'fix_string_encoding'));
		
		#add_filter('bp_core_get_userid_from_nicename', 	array(&$this, 'bp_core_get_userid_from_nicename_fix'));
	}



	


	#function bp_core_get_userid_from_nicename_fix($user_nicename) {
	#	_log($user_nicename);
	#
	#
	#	global $wpdb;
	#	return $wpdb->get_var( $wpdb->prepare( "SELECT ID FROM {$wpdb->users} WHERE user_nicename = %s", utf8_encode($user_nicename) ) );
	#}
	
	
	/*
	 * Replace wordpress login link with mediawiki one (some day...)
	 */
	function mw_login_url($link) {
		return $link;
	}


	/*
	 * MediaWiki uses logins with first letter uppercase and rest case sensitive. 
	 * And then the rest can be anything from cyrilics to chinese...
	 * Wordpress MU/BP wants everything to be lowercase. 
	 * So figure out...
	 *
	 * See MediaWiki sources for reference: 
	 * https://svn.wikimedia.org/doc/classUser.html#a75957f369ce60cdce57011e13a4250c7
	 * https://svn.wikimedia.org/doc/classUser.html#aae4a9d5c51fb9fdcd68637f615194540
	 */
	function mw_sanitize_username($username, $raw_username, $strict) {

		// Security measures
		$username = wp_strip_all_tags($raw_username);
		#$username = preg_replace('|%([a-fA-F0-9][a-fA-F0-9])|', '', $username);
		#$username = preg_replace('/&.+?;/', '', $username);

		#if ( $strict )
		       # $username = preg_replace('|[^a-zA-Z0-9 _.\-@]|i', '', $username);

		#$username = preg_replace('|\s+|', ' ', $username);

		#$username = str_replace('Ã©', 'é', $username);

		// Using ucfirst($username) Will work for latin letters, but let's not forget utf8!
		$fc = mb_strtoupper(mb_substr($username, 0, 1));
		$username = $fc.mb_substr($username, 1);
		
		return $username;
	}


	/*
	 * Auth against MediaWiki API
	 */
	function mw_authenticate( $username, $password ) {

		if( empty($username) || empty($password) ) return;

		$username = sanitize_user($username, $username);
		$password = trim($password);
		
		require_once("mediawikibot.class.php");
		
		
		try
		{
		
		    $wiki = new MediaWikiBot( array(
		    
		    	"domain" =>		$this->domain,
		    	"wiki"	=> 		$this->wiki,
		    	"useragent" => 	'WordPress/' . get_bloginfo('version') . '; ' . home_url(),
		    	"username" => 	$username,
		    	"password" => 	$password
		    
		    ) );

		    $mw_user = $wiki->login();
		    
		    $mw_user_id = ($mw_user['login']['result'] == "Success" && isset($mw_user['login']['lguserid'])) ? $mw_user['login']['lguserid'] : false;

		    if ( $mw_user_id !== false ) {
		        
				$user = wp_set_current_user($mw_user_id, $username);
				
		        if ( is_wp_error($user) ) {
			        do_action('wp_login_failed', $username);
					exit;
		        }
		        
				wp_set_auth_cookie($mw_user_id);

				// the wp_login action is used by a lot of plugins, so in case...
				do_action('wp_login', $mw_user_id);
				
				wp_redirect( home_url() ); 
				
				exit;
				
		        /*
		        if( $user->ID == 0 ) {
		        	// Should create new user here?
		        }
		        */
		
		    }
		    else {
			    do_action('wp_login_failed', $username);
		        $user = new WP_Error( 'denied', __("<strong>ERROR</strong>" ) );
		    }
		}
		catch ( Exception $e )
		{
		    $user = new WP_Error( 'denied', __("<strong>ERROR</strong>: ".$e->getMessage() ) );
		}
		
		return $user;
		
	}


	/*
	 * Handle failed login to WP
	 */
     function hw_login_fail( $username ) {
          $referrer = $_SERVER['HTTP_REFERER'];  // where did the post submission come from?
          // if there's a valid referrer, and it's not the default log-in screen
          if ( !empty($referrer) && !strstr($referrer,'wp-login') && !strstr($referrer,'wp-admin') ) {
               wp_redirect(home_url() . '/?login=failed' );  // let's append some information (login=failed) to the URL for the theme to use
               exit;
          }
     }


	/*
	 * Logout from MediaWiki API
	 */
	function mw_logout() {
		//_log("->mw_logout");
		
		require_once("mediawikibot.class.php");
		
		$wiki = new MediaWikiBot(array(
		
		    "domain" =>		$this->domain,
		    "wiki"	=> 		$this->wiki,
		    "useragent" => 	'WordPress/' . get_bloginfo('version') . '; ' . home_url(),
		
		));
		
		$wiki->logout();
	  
	}


	/**
	 * Display MW registration link
	 * Filters function wp_register(), see http://core.trac.wordpress.org/browser/trunk/wp-includes/general-template.php#L323
	 *
	 * @return string|null String when retrieving, null when displaying.
	 */
	#if(!function_exists("register_link")):
	function register_link($link="") {
	
	    $before = '';
	    $after = '';
	    	
	    // @todo maps redirect:
	    $maps = false;
	    $return_to = ($maps == true) ? 'Maps.hitchwiki.org' : 'Main_Page';
	
	    if(!is_user_logged_in())
	        $link = '<a href="' . $this->domain . $this->wiki . '/index.php?title=Special:UserLogin&type=signup&returnto='.$return_to.'">' . __('Register') . '</a>';
	    #else
	        #$link =  '<a href="' . admin_url() . '">' . __('Site Admin') . '</a>';
	
	    return $before . $link . $after;
	}
	#endif;


	/*
	 * Allow Capital Letters In Username (BuddyPress)
	 * Allows to use uppercase Latin letters when registering a new user.
	 * Version: 0.3-trunk
	 * http://ru.forums.wordpress.org/topic/3738
	 * Author: Sergey Biryukov http://sergeybiryukov.ru/
	 *
	 * From http://code.google.com/p/l10n-ru/source/browse/trunk/wp-plugins/allow-capital-letters-in-username/allow-capital-letters-in-username.php
	 */
	function acl_bp_core_validate_user_signup($result) {
	        $illegal_names = get_site_option('illegal_names');

	        if ( validate_username($result['user_name']) && !in_array($result['user_name'], (array)$illegal_names) ) {
	                $error_index = array_search(__('Only lowercase letters and numbers allowed', 'buddypress'), $result['errors']->errors['user_name']);
	                if ( isset($error_index) ) {
	                        unset($result['errors']->errors['user_name'][$error_index]);
	                        sort($result['errors']->errors['user_name']);
	                }
	        }
	        
	        return $result;
	}
	
	

	/*
	 * By normal WP create user -way we would have wp_capabilities and such created to "wp_usermeta" table.
	 * This one adds them when user first times logs in.
	 */
	function fix_user_roles() {
		$current_user = wp_get_current_user();
		
		// If user is logged in and doesn't have role at all, do the magic...
		if( !empty($current_user->data) && empty($current_user->roles) ) {
	
			// Update default role for the user
			wp_update_user( array (
							'ID' => $current_user->data->ID, 
							'role' => get_option('default_role') // in most cases gonna be "subscriber"
							) );
		}

	}//fix_user_roles


	/*
	 * WP uses gettext for translations
	 * We hook into it's input to remove some strings
	 */
	function adjust_gettext($text) {

		// Removes the ability for users to change/reset their passwords.
		// Yea, such a hack. ;-)
		return str_replace( array('Lost your password?', 'Lost your password'), '', $text ); 

	}




	/*
	 * Somewhere along the process of MW API <> WP, usernames with special letters get double encoded.
	 * Use this to roll them back.
	 *
	 * Eg. "Ã©" would be again "é".
	 */
	function fix_string_encoding($str) {

		// https://github.com/neitanod/forceutf8
		@require_once("class.encoding.php");
		$encoder = new Encoding();

		return $encoder->fixUTF8( $str );
	}
	/*
	 * Fix whole user object at once, works for both WordPress and BuddyPress objects 
	 */
	function fix_user_encoding($user) {

		// https://github.com/neitanod/forceutf8
		@require_once("class.encoding.php");
		$encoder = new Encoding();


		// Targeting mainly BuddyPress
		if(!empty($user->user_login)) $user->user_login = $encoder->fixUTF8( $user->user_login );

		if(!empty($user->display_name)) $user->display_name = $encoder->fixUTF8( $user->display_name );

		if(!empty($user->user_nicename)) $user->user_nicename = $encoder->fixUTF8( $user->user_nicename );
		
		
		// Targeting native WP user object
		if(!empty($user->data->user_login)) $user->data->user_login = $encoder->fixUTF8( $user->data->user_login );

		if(!empty($user->data->display_name)) $user->data->display_name = $encoder->fixUTF8( $user->data->display_name );

		if(!empty($user->data->user_nicename)) $user->data->user_nicename = $encoder->fixUTF8( $user->data->user_nicename );


		return $user;
	}



	/*
	 * Simply used to disable some functionality via hooks
	 */
	function disable_function() { return false; }
	
}



// Load the plugin hooks, etc.
$MWAuth = new MWAuthPlugin();



/*
 * These are functions we want to replace from wp-includes/pluggable.php
 * Keep looking changes for these when WP updates
 */


if ( !function_exists('get_user_by') ) :
/**
 * Retrieve user info by a given field
 *
 * @since 2.8.0
 *
 * @param string $field The field to retrieve the user with. id | slug | email | login
 * @param int|string $value A value for $field. A user ID, slug, email address, or login name.
 * @return bool|object False on failure, WP_User object on success
 */
function get_user_by( $field, $value ) {
	#_log("->get_user_by(".$field .", ".$value.")");

	#if($field == "login") {
	#	global $MWAuth;
	#	$value = $MWAuth->fix_username_encoding( $value );
	#}
	#_log("Re: ".$value);

	$userdata = WP_User::get_data_by( $field, $value );

	if ( !$userdata )
		return false;

	$user = new WP_User;
	$user->init( $userdata );

	/*
	 * Fix double encoding back to normal for some fields
	 */
	#global $MWAuth;
	#$user = $MWAuth->fix_user_encoding($user);

	return $user;
}
endif;




if ( !function_exists('wp_get_current_user') ) :
/**
 * Retrieve the current user object.
 *
 * @since 2.0.3
 *
 * @return WP_User Current user WP_User object
 */
function wp_get_current_user() {
	global $current_user;

	get_currentuserinfo();

	global $MWAuth;
	$current_user = $MWAuth->fix_user_encoding( $current_user );

	return $current_user;
}
endif;



/*
 * Difference with original WP: 
 * Allow spaces and special letters in urls
 */
if ( !function_exists('wp_sanitize_redirect') ) :
/**
 * Sanitizes a URL for use in a redirect.
 *
 * @since 2.3
 *
 * @return string redirect-sanitized URL
 **/
function wp_sanitize_redirect($location) {
	// Was:
	//$location = preg_replace('|[^a-z0-9-~+_.?#=&;,/:%!]|i', '', $location);

	// Allow special stuff:
	$location = preg_replace('|[^a-z0-9 -~+_.?#=!&;,/:%@$\|*\'()\\x80-\\xff]|i', '', $location);
	
	$location = wp_kses_no_null($location);

	// remove %0d and %0a from location
	$strip = array('%0d', '%0a', '%0D', '%0A');
	$location = _deep_replace($strip, $location);
	return $location;
}
endif;




/*
 * These are required by some older users?
 */
if ( !function_exists('wp_hash_password') ) :
function wp_hash_password($password) {
    return ":A:".md5($password);
}
endif;
if ( !function_exists('wp_check_password') ) :
function wp_check_password($password, $hash, $user_id = '') {
    if (md5($password) === $hash) 
        return true;

    if (':A:'.md5($password) === $hash) 
        return true;

    if (":B:$user_id:".md5("$user_id-".md5($password)) === $hash) 
        return true;

    return false;
}
endif;

