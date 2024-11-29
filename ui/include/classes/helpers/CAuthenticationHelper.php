<?php declare(strict_types = 0);
/*
** Zabbix
** Copyright (C) 2001-2024 Zabbix SIA
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
**/


/**
 * A class for accessing once loaded parameters of Authentication API object.
 */
class CAuthenticationHelper {

	public const AUTHENTICATION_TYPE = 'authentication_type';
	public const HTTP_AUTH_ENABLED = 'http_auth_enabled';
	public const HTTP_CASE_SENSITIVE = 'http_case_sensitive';
	public const HTTP_LOGIN_FORM = 'http_login_form';
	public const HTTP_STRIP_DOMAINS = 'http_strip_domains';
	public const LDAP_BASE_DN = 'ldap_base_dn';
	public const LDAP_BIND_DN = 'ldap_bind_dn';
	public const LDAP_BIND_PASSWORD = 'ldap_bind_password';
	public const LDAP_CASE_SENSITIVE = 'ldap_case_sensitive';
	public const LDAP_CONFIGURED = 'ldap_configured';
	public const LDAP_HOST = 'ldap_host';
	public const LDAP_PORT = 'ldap_port';
	public const LDAP_SEARCH_ATTRIBUTE = 'ldap_search_attribute';
	public const PASSWD_CHECK_RULES = 'passwd_check_rules';
	public const PASSWD_MIN_LENGTH = 'passwd_min_length';
	public const SAML_AUTH_ENABLED = 'saml_auth_enabled';
	public const SAML_CASE_SENSITIVE = 'saml_case_sensitive';
	public const SAML_ENCRYPT_ASSERTIONS = 'saml_encrypt_assertions';
	public const SAML_ENCRYPT_NAMEID = 'saml_encrypt_nameid';
	public const SAML_IDP_ENTITYID = 'saml_idp_entityid';
	public const SAML_NAMEID_FORMAT = 'saml_nameid_format';
	public const SAML_SIGN_ASSERTIONS = 'saml_sign_assertions';
	public const SAML_SIGN_AUTHN_REQUESTS = 'saml_sign_authn_requests';
	public const SAML_SIGN_LOGOUT_REQUESTS = 'saml_sign_logout_requests';
	public const SAML_SIGN_LOGOUT_RESPONSES = 'saml_sign_logout_responses';
	public const SAML_SIGN_MESSAGES = 'saml_sign_messages';
	public const SAML_SLO_URL = 'saml_slo_url';
	public const SAML_SP_ENTITYID = 'saml_sp_entityid';
	public const SAML_SSO_URL = 'saml_sso_url';
	public const SAML_USERNAME_ATTRIBUTE = 'saml_username_attribute';

	private static $params = [];
	private static $params_public = [];

	/**
	 * Get the value of the given Authentication API object's field.
	 *
	 * @param string $field
	 *
	 * @throws Exception
	 *
	 * @return string
	 */
	public static function get(string $field): string {
		if (!self::$params) {
			self::$params = API::Authentication()->get([
				'output' => [
					'authentication_type', 'http_auth_enabled', 'http_login_form', 'http_strip_domains',
					'http_case_sensitive', 'ldap_configured', 'ldap_host', 'ldap_port', 'ldap_base_dn',
					'ldap_search_attribute', 'ldap_bind_dn', 'ldap_case_sensitive', 'ldap_bind_password',
					'saml_auth_enabled', 'saml_idp_entityid', 'saml_sso_url', 'saml_slo_url', 'saml_username_attribute',
					'saml_sp_entityid', 'saml_nameid_format', 'saml_sign_messages', 'saml_sign_assertions',
					'saml_sign_authn_requests', 'saml_sign_logout_requests', 'saml_sign_logout_responses',
					'saml_encrypt_nameid', 'saml_encrypt_assertions', 'saml_case_sensitive', 'passwd_min_length',
					'passwd_check_rules'
				]
			]);

			if (self::$params === false) {
				throw new Exception(_('Unable to load authentication API parameters.'));
			}
		}

		return self::$params[$field];
	}

	/**
	 * Get the value of the given Authentication API object's field available to parts of the UI without authentication.
	 *
	 * @param string $field
	 *
	 * @return string
	 */
	public static function getPublic(string $field): string {
		if (!self::$params_public) {
			self::$params_public = CAuthentication::getPublic();
		}

		return self::$params_public[$field];
	}
}
