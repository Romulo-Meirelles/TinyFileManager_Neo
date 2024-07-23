<?php
/**
 * Mr. Meirelles | Tiny File Manager V3.0.0
 * @author Rômulo Meirelles Programmer
 * @email romulomeirelles@hotmail.com
 * @github https://github.com/Romulo-Meirelles/TinyFileManager_Neo
 * @link https://github.com/Romulo-Meirelles
 */
 
 
// Auth with login/password
// set true/false to enable/disable it
// Is independent from IP white- and blacklisting
$use_auth = true;

// Login user name and password
// Users: array('Username' => 'Password', 'Username2' => 'Password2', ...)
// Generate secure password hash - https://tinyfilemanager.github.io/docs/pwd.html
$auth_users = array(
    'admin' => '$2y$10$oFjSKOA5fqyNKbOHdgI8buEmYXX60g/0KJYGJVwScbGPX.2K8D/Wu',
    'user' => '$2y$10$W8fxLM6EgVrAKEJDvtL.ge62Q3aLp8N7n6FfHLFb7bDJA8MYGsQ3i'
);

// Readonly users
// e.g. array('users', 'guest', ...)
$readonly_users = array(
    'user'
);

// Global readonly, including when auth is not being used
$global_readonly = false;

// user specific directories
// array('Username' => 'Directory path', 'Username2' => 'Directory path', ...)
$directories_users = array();

?>