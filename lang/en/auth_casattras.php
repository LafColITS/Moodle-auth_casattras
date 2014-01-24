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
 * Strings for component 'auth_casattras', language 'en'.
 *
 * @package   auth_casattras
 * @author Adam Franco
 * @copyright 2014 Middlebury College  {@link http://www.middlebury.edu}
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

$string['pluginname'] = 'CAS server (SSO) with user-attribute release';
$string['auth_casattrasdescription'] = 'This method uses a CAS server (Central Authentication Service) to authenticate users in a Single Sign On environment (SSO). User attributes are returned in the CAS authentication response rather than from an LDAP server. This allows usage of CAS servers that are not backed by an LDAP server or are backed by multiple LDAP servers. If the given username and password are valid according to CAS, Moodle creates a new user entry in its database, taking user attributes from the CAS authentication response if configured.';
