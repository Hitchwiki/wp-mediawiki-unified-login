Hitchwiki Unified login for WP
==============================

Setup:

- We use MediaWiki login table

- In Wordpress wp_users is mirrored against MediaWiki's table

- Wordpress plugin does a trick and two to use MediaWiki formatted users
	- First letter uppercase the rest lower case + allow special chars
	- Forbid changing passwords from WP
	- Forbid registering accounts from WP
	- Give WP user roles for newly logged in users