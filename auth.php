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
}
