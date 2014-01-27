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

require_once($CFG->dirroot.'/auth/cas/CAS/CAS.php');

/**
 * CAS-Attras authentication plugin.
 */
class auth_plugin_casattras extends auth_plugin_base {

    /**
     * Constructor with initialization.
     */
    public function __construct() {
        $this->authtype = 'casattras';
        $this->roleauth = 'auth_casattras';
        $this->errorlogtag = '[AUTH CAS-ATTRAS] ';
        $this->config = get_config('auth/casattras');
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

        return true;
    }
}
