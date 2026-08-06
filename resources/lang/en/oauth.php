<?php

declare(strict_types=1);

/**
 * English copy for the OAuth2 plugin's user-facing screens.
 *
 * Reached as 'oauth2::oauth.*'. Namespaced because "oauth" is a group name
 * another plugin could plausibly ship, and an unnamespaced collision would
 * silently serve one plugin's wording from another's catalogue.
 *
 * A project can reword any of this without forking the plugin by placing its
 * own file at {project-lang}/oauth2/{locale}/oauth.php — only the keys it
 * defines are overridden.
 */
return [
    // --- Consent screen ------------------------------------------------------
    // The single most security-sensitive screen in the plugin: it is where a
    // user decides what an application may do on their behalf. The wording has
    // to make the grant and its scope unmistakable.
    'consent' => [
        'title'     => 'Authorize :client',
        'request'   => ':client is requesting access to your account.',
        'abilities' => 'It will be able to:',
        'deny'      => 'Deny',
        'allow'     => 'Allow',
    ],

    // --- Device flow (RFC 8628) ---------------------------------------------
    'device' => [
        'title'          => 'Connect a device',
        'prompt'         => 'Enter the code shown on your device.',
        'placeholder'    => 'XXXX-XXXX',
        'deny'           => 'Deny',
        'approve'        => 'Approve',
        // Deliberately does not distinguish invalid from expired from used:
        // telling an attacker which of the three a guessed code hit is a free
        // oracle for enumerating live codes.
        'invalid'        => 'That code is invalid, expired, or already used.',
        'approved'       => 'Device approved. You can return to your device.',
        'denied'         => 'Device denied.',
        'login_required' => 'Login required.',
    ],

    // --- Admin surface -------------------------------------------------------
    'admin' => [
        'title'            => 'OAuth2 Admin',
        'tab_clients'      => 'Clients',
        'tab_scopes'       => 'Scopes',
        'tab_grants'       => 'Grants',
        'clients_intro'    => 'Every OAuth client registered in this tenant.',
        'scopes_title'     => 'Scope catalogue',
        'grants_title'     => 'Authorized grants',
        'grants_intro'     => 'Every active refresh-token grant across all users.',
        'loading'          => 'Loading…',
        'col_name'         => 'Name',
        'col_owner'        => 'Owner',
        'col_type'         => 'Type',
        'col_scopes'       => 'Scopes',
        'col_status'       => 'Status',
        'empty_clients'    => 'No clients yet.',
        'empty_scopes'     => 'No scopes registered.',
        'empty_grants'     => 'No active grants.',
        'register_title'   => 'Register OAuth client',
        'field_scopes'     => 'Scopes (space-separated)',
        'scopes_hint'      => 'Every scope must exist in the catalogue.',
        'field_grants'     => 'Grant types',
        'field_public'     => 'Public client (PKCE) — off = confidential',
        'cancel'           => 'Cancel',
        'create'           => 'Create client',
    ],
];
