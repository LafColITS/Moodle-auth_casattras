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
    die('Direct access to this script is forbidden.'); // It must be included from a Moodle page.
}

require_once($CFG->libdir.'/authlib.php');
require_once($CFG->dirroot.'/auth/cas/CAS/CAS.php');

/**
 * CAS-Attras authentication plugin.
 *
 * @package auth_casattras
 * @author Adam Franco
 * @copyright 2014 Middlebury College  {@link http://www.middlebury.edu}
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class auth_plugin_casattras extends auth_plugin_base {

    /** @var boolean Flag to ensure that phpCAS only gets initialized once. */
    protected static $casinitialized = false;

    /**
     * Constructor with initialization.
     */
    public function __construct() {
        $this->authtype = 'casattras';
        $this->roleauth = 'auth_casattras';
        $this->errorlogtag = '[AUTH CAS-ATTRAS] ';
        $this->config = get_config('auth_casattras');

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
            \core\session\manager::gc(); // Remove stale sessions.

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
     * Initialize phpCAS configuration.
     *
     */
    protected function init_cas() {
        global $CFG;
        if (self::$casinitialized) {
            return;
        }

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

        if ($this->config->certificatecheck && $this->config->certificatepath) {
            phpCAS::setCasServerCACert($this->config->certificatepath);
        } else {
            // Don't try to validate the server SSL credentials.
            phpCAS::setNoCasServerValidation();
        }
    }

    /**
     * Hook for overriding behaviour of login page.
     * This method is called from login/index.php page for all enabled auth plugins.
     */
    public function loginpage_hook() {
        global $frm;  // Can be used to override submitted login form.
        global $user; // Can be used to replace authenticate_user_login().

        // Return if CAS enabled and settings are not specified yet.
        if (empty($this->config->hostname)) {
            return;
        }

        // Don't do CAS authentication if the username/password form was submitted.
        // CAS redirects will always be GET requests, so any posts shouldn't be handled by CAS.
        $username = optional_param('username', '', PARAM_RAW);
        $ticket = optional_param('ticket', '', PARAM_RAW);
        if ($_SERVER['REQUEST_METHOD'] == 'POST' || (!empty($username) && empty($ticket))) {
            return;
        }

        // Configure phpCAS.
        $this->init_cas();

        // Bypass CAS authentication if the NOCAS pramameter is present.
        // If multi-auth isn't enabled usersn't won't be presented with a link that includes this parameter,
        // but it can be manually included in the URL to allow manual accounts to log without CAS.
        $usecas = optional_param('authCASattras', '', PARAM_RAW);
        if ($usecas == 'NOCAS') {
            return;
        }

        if ($this->config->multiauth) {
            // Show authentication form for multi-authentication
            // test pgtIou parameter for proxy mode (https connection
            // in background from CAS server to the php server).
            if ($usecas != 'CAS' && !isset($_GET['pgtIou'])) {
                global $CFG, $PAGE, $OUTPUT;
                $site = get_site();
                $PAGE->set_url('/login/index.php');
                $casform = get_string('CASform', 'auth_cas');
                $PAGE->navbar->add($casform);
                $PAGE->set_title("$site->fullname: $casform");
                $PAGE->set_heading($site->fullname);
                echo $OUTPUT->header();
                include($CFG->dirroot.'/auth/casattras/cas_form.html');
                echo $OUTPUT->footer();
                exit();
            }
        }

        // If already authenticated.
        if (phpCAS::checkAuthentication()) {
            if (empty($frm)) {
                $frm = new stdClass;
            }
            $frm->username = phpCAS::getUser();
            $frm->password = 'passwdCas';
            return;
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
        return phpCAS::isAuthenticated() && (trim(core_text::strtolower(phpCAS::getUser())) == $username);
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
        if (!phpCAS::isAuthenticated() || trim(core_text::strtolower(phpCAS::getUser())) != $username) {
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
