<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Authentication Plugin: CAS Authentication with attribute release
 *
 * Authentication using CAS (Central Authentication Server) with attributes returned from the CAS server
 *
 * @package auth_casattras
 * @author Adam Franco
 * @copyright 2014 Middlebury College  {@link http://www.middlebury.edu}
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');    //  It must be included from a Moodle page.
}

require_once($CFG->libdir.'/authlib.php');

/**
 * CAS-Attras authentication plugin.
 */
class auth_plugin_casattras extends auth_plugin_base {

    /**
     * Flag to ensure that phpCAS only gets initialized once.
     */
    protected static $casinitialized = false;

    /**
     * Constructor with initialization.
     */
    public function __construct() {
        $this->authtype = 'casattras';
        $this->roleauth = 'auth_casattras';
        $this->errorlogtag = '[AUTH CAS-ATTRAS] ';
        $this->config = get_config('auth/casattras');

        // Verify that the CAS auth plugin is not enabled, disable this plugin (casattras) if so, because they will conflict.
        if (is_enabled_auth('cas') && is_enabled_auth('casattras')) {
            // This code is modeled on that in moodle/admin/auth.php.
            global $CFG;
            get_enabled_auth_plugins(true);
            if (empty($CFG->auth)) {
                $authsenabled = array();
            } else {
                $authsenabled = explode(',', $CFG->auth);
            }
            $key = array_search('casattras', $authsenabled);
            if ($key !== false) {
                unset($authsenabled[$key]);
                set_config('auth', implode(',', $authsenabled));
            }
            if ('casattras' == $CFG->registerauth) {
                set_config('registerauth', '');
            }
            session_gc(); // Remove stale sessions.

            $returnurl = new moodle_url('/admin/settings.php', array('section' => 'manageauths'));
            print_error('casattras_disabled_by_cas', 'auth_casattras', $returnurl, null,
                get_string('casattras_disabled_by_cas', 'auth_casattras'));
        }
    }

    /**
     * Return the properly translated human-friendly title of this auth plugin
     *
     * @todo Document this function
     */
    public function get_title() {
        $title = parent::get_title();
        if (is_enabled_auth('cas')) {
            $title .= ' - '.get_string('cas_conflict_warning', 'auth_casattras');
        }
        return $title;
    }

    /**
     * Returns true if this authentication plugin is "internal".
     *
     * Internal plugins use password hashes from Moodle user table for authentication.
     *
     * @return bool
     */
    public function is_internal() {
        return false;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $page An object containing all the data for this page.
     */
    public function config_form($config, $err, $userfields) {
        global $CFG, $OUTPUT;
        include($CFG->dirroot.'/auth/casattras/config.html');
    }

    /**
     * A chance to validate form data, and last chance to
     * do stuff before it is inserted in config_plugin
     * @param object object with submitted configuration settings (without system magic quotes)
     * @param array $err array of error messages
     */
    public function validate_form($form, &$err) {
        $certificatepath = trim($form->certificatepath);
        if ($form->certificatecheck && empty($certificatepath)) {
            $err['certificatepath'] = get_string('auth_casattras_certificate_path_empty', 'auth_casattras');
        }
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     *
     * @param object object with submitted configuration settings (without system magic quotes)
     */
    public function process_config($config) {
        // CAS settings.
        if (!isset($config->hostname)) {
            $config->hostname = '';
        }
        if (!isset($config->port)) {
            $config->port = '';
        }
        if (!isset($config->casversion)) {
            $config->casversion = '';
        }
        if (!isset($config->baseuri)) {
            $config->baseuri = '';
        }
        if (!isset($config->language)) {
            $config->language = '';
        }
        if (!isset($config->proxycas)) {
            $config->proxycas = '';
        }
        if (!isset($config->logoutcas)) {
            $config->logoutcas = '';
        }
        if (!isset($config->multiauth)) {
            $config->multiauth = '';
        }
        if (!isset($config->certificatecheck)) {
            $config->certificatecheck = '';
        }
        if (!isset($config->certificatepath)) {
            $config->certificatepath = '';
        }
        if (!isset($config->logoutreturnurl)) {
            $config->logoutreturnurl = '';
        }

        // Save CAS settings.
        set_config('hostname', trim($config->hostname), 'auth/casattras');
        set_config('port', trim($config->port), 'auth/casattras');
        set_config('casversion', $config->casversion, 'auth/casattras');
        set_config('baseuri', trim($config->baseuri), 'auth/casattras');
        set_config('language', $config->language, 'auth/casattras');
        set_config('proxycas', $config->proxycas, 'auth/casattras');
        set_config('logoutcas', $config->logoutcas, 'auth/casattras');
        set_config('multiauth', $config->multiauth, 'auth/casattras');
        set_config('certificatecheck', $config->certificatecheck, 'auth/casattras');
        set_config('certificatepath', $config->certificatepath, 'auth/casattras');
        set_config('logoutreturnurl', $config->logoutreturnurl, 'auth/casattras');

        // Update user authentication types if requested.
        if (!empty($config->convert_authtype)) {
            global $DB;
            if ($config->convert_authtype == 'cas_to_casattras') {
                $DB->set_field('user', 'auth', 'casattras', array('auth' => 'cas'));
            } else if ($config->convert_authtype == 'casattras_to_cas') {
                $DB->set_field('user', 'auth', 'cas', array('auth' => 'casattras'));
            }
        }

        return true;
    }

    /**
     * Initialize phpCAS configuration.
     *
     */
    protected function init_cas() {
        global $CFG;
        if (self::$casinitialized) {
            return;
        }

        if (class_exists('phpCAS')) {
            throw new Exception(get_string('phpcas_already_included', 'auth_casattras'));
        }

        require_once($CFG->dirroot.'/auth/casattras/phpCAS/CAS.php');

        // Make sure phpCAS doesn't try to start a new PHP session when connecting to the CAS server.
        if ($this->config->proxycas) {
            phpCAS::proxy(
                constant($this->config->casversion),
                $this->config->hostname,
                (int) $this->config->port,
                $this->config->baseuri,
                false);
        } else {
            phpCAS::client(
                constant($this->config->casversion),
                $this->config->hostname,
                (int) $this->config->port,
                $this->config->baseuri,
                false);
        }
        self::$casinitialized = true;

        // If Moodle is configured to use a proxy, phpCAS needs some curl options set.
        if (!empty($CFG->proxyhost) && !is_proxybypass($this->config->hostname)) {
            phpCAS::setExtraCurlOption(CURLOPT_PROXY, $CFG->proxyhost);
            if (!empty($CFG->proxyport)) {
                phpCAS::setExtraCurlOption(CURLOPT_PROXYPORT, $CFG->proxyport);
            }
            if (!empty($CFG->proxytype)) {
                // Only set CURLOPT_PROXYTYPE if it's something other than the curl-default http.
                if ($CFG->proxytype == 'SOCKS5') {
                    phpCAS::setExtraCurlOption(CURLOPT_PROXYTYPE, CURLPROXY_SOCKS5);
                }
            }
            if (!empty($CFG->proxyuser) and !empty($CFG->proxypassword)) {
                phpCAS::setExtraCurlOption(CURLOPT_PROXYUSERPWD, $CFG->proxyuser.':'.$CFG->proxypassword);
                if (defined('CURLOPT_PROXYAUTH')) {
                    // Any proxy authentication if PHP 5.1.
                    phpCAS::setExtraCurlOption(CURLOPT_PROXYAUTH, CURLAUTH_BASIC | CURLAUTH_NTLM);
                }
            }
        }

        if ($this->config->certificate_check && $this->config->certificate_path) {
            phpCAS::setCasServerCACert($this->config->certificate_path);
        } else {
            // Don't try to validate the server SSL credentials.
            phpCAS::setNoCasServerValidation();
        }
    }

    /**
     * Hook for overriding behaviour of login page.
     * This method is called from login/index.php page for all enabled auth plugins.
     *
     * @global object
     * @global object
     */
    public function loginpage_hook() {
        global $frm;  // Can be used to override submitted login form.
        global $user; // Can be used to replace authenticate_user_login().

        // Return if CAS enabled and settings are not specified yet.
        if (empty($this->config->hostname)) {
            return;
        }

        // Configure phpCAS.
        $this->init_cas();

        // If already authenticated.
        if (phpCAS::checkAuthentication()) {
            $frm->username = phpCAS::getUser();
            $frm->password = 'passwdCas';
            return;
        }

        if ($this->config->multiauth) {
            $usecas = optional_param('authCASattras', '', PARAM_RAW);
            if ($usecas == 'NOCAS') {
                return;
            }

            // Show authentication form for multi-authentication
            // test pgtIou parameter for proxy mode (https connection
            // in background from CAS server to the php server).
            if ($usecas != 'CAS' && !isset($_GET['pgtIou'])) {
                global $CFG, $PAGE, $OUTPUT;
                $site = get_site();
                $PAGE->set_url('/login/index.php');
                $PAGE->navbar->add(get_string('CASform', 'auth_casattras'));
                $PAGE->set_title("$site->fullname: $CASform");
                $PAGE->set_heading($site->fullname);
                echo $OUTPUT->header();
                include($CFG->dirroot.'/auth/casattras/cas_form.html');
                echo $OUTPUT->footer();
                exit();
            }
        }

        // Force CAS authentication (if needed).
        if (!phpCAS::isAuthenticated()) {
            phpCAS::forceAuthentication();
        }
    }

    /**
     * Authenticates user against CAS
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     * @return bool Authentication success or failure.
     */
    public function user_login ($username, $password) {
        $this->init_cas();
        return phpCAS::isAuthenticated() && (trim(textlib::strtolower(phpCAS::getUser())) == $username);
    }

    /**
     * Read user information from external database and returns it as array().
     * Function should return all information available. If you are saving
     * this information to moodle user-table you should honour synchronisation flags
     *
     * @param string $username username
     *
     * @return mixed array with no magic quotes or false on error
     */
    public function get_userinfo($username) {
        if (!phpCAS::isAuthenticated() || trim(textlib::strtolower(phpCAS::getUser())) != $username) {
            return array();
        }

        $casattras = phpCAS::getAttributes();
        $moodleattras = array();

        foreach ($this->userfields as $field) {
            $casfield = $this->config->{"field_map_$field"};
            if (!empty($casfield) && !empty($casattras[$casfield])) {
                $moodleattras[$field] = $casattras[$casfield];
            }
        }

        return $moodleattras;
    }

    /**
     * Logout from the CAS
     *
     */
    public function prelogout_hook() {
        global $CFG;

        if (!empty($this->config->logoutcas)) {
            $backurl = $CFG->wwwroot;
            $this->init_cas();
            phpCAS::logoutWithURL($backurl);
        }
    }
}
