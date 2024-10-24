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
 * Version details.
 *
 * @package auth_casattras
 * @author Adam Franco
 * @copyright 2014 Middlebury College  {@link http://www.middlebury.edu}
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @package auth_casattras
 */

defined('MOODLE_INTERNAL') || die();

$plugin->version = 2022120602;      // The current plugin version (Date: YYYYMMDDXX).
$plugin->release = 'v4.1.2';
$plugin->requires = 2022111800;      // Requires this Moodle version.
$plugin->component = 'auth_casattras';  // Full name of the plugin (used for diagnostics).
$plugin->maturity = MATURITY_STABLE;
$plugin->dependencies = array(
    'auth_cas' => 2022112800,
);
