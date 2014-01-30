CAS server (SSO) with user-attribute release
============================================

This is an authentication plugin for Moodle that authenticates users via a Central Authentication Service (CAS) server and
populates the Moodle user-account's attributes from user-attributes included in the CAS response.

This method does **not** make use of LDAP for user-attribute lookup, allowing its use in situations where there is no LDAP server
that includes user information, or there are multiple LDAP servers that include user information.

This authentication method makes use of the attributes returned by the phpCAS library's `phpCAS::getAttributes()` function and which
are often returned from modern CAS servers.

Requirements
------------

*  A CAS server that supports attribute-release via one of...
    1. The SAML 1.1 protocol
    2. The CAS 2.0 protocol with the serviceValidate JSP customized to include attributes
    3. [coming soon] The CAS 3.0 protocol

Installation
------------

1.  Download the source for this authentication module and place it in `moodle/auth/casattras/`.
    This can be accomplished with

            cd /path/to/my/moodle/
            git clone https://github.com/middlebury/Moodle-auth_casattras.git auth/casattras

2.  Log into Moodle as a site-adminstrator. You should be prompted to run a database update to install the plugin.

Configuration
-------------
1. Log into Moodle as a site-administrator.
2. If you don't already, make sure that you have a **manual** authentication-type admin account that you can log in with.
3. Log in with the **manual** authentication-type admin account to ensure that you won't get locked out while changing around
    authentication settings.
4. In Moodle, go to *Site Administration* -> *Plugins* -> *Authentication* -> *Manage Authentication*
5. Edit the settings for **CAS server (SSO) with user-attribute release** to fit your CAS server.
6. (Optional) If you are migrating from using the built-in CAS module you can choose to convert users' authentiation types from
    the built-in CAS authentication type to **CAS server (SSO) with user-attribute release**. Not that this setting allows you to
    convert users' authentication types back to the built-in **CAS server (SSO)** authentication type if needed.
7. Save the configuration.
8. Disable the built-in **CAS server (SSO)** authentication type. This authentication plugin uses a newer version of phpCAS which
    would conflict with the built-in **CAS server (SSO)** authentication type, so both cannot be enabled at the same time.
9. Enable the **CAS server (SSO) with user-attribute release** authentication type.
