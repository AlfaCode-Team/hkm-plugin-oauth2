<?php

declare(strict_types=1);

/**
 * French copy for the OAuth2 plugin's user-facing screens.
 *
 * The consent screen is translated for precision rather than fluency. It is
 * where a user grants an application access to their account, so the French
 * has to make the grant and its scope as unmistakable as the English does —
 * a softer, more idiomatic phrasing that blurs what is being authorised would
 * be a worse translation, not a better one.
 */
return [
    // --- Écran de consentement ----------------------------------------------
    'consent' => [
        'title'     => 'Autoriser :client',
        'request'   => ':client demande l\'accès à votre compte.',
        'abilities' => 'Cette application pourra :',
        'deny'      => 'Refuser',
        'allow'     => 'Autoriser',
    ],

    // --- Flux par code d'appareil (RFC 8628) --------------------------------
    'device' => [
        'title'          => 'Connecter un appareil',
        'prompt'         => 'Saisissez le code affiché sur votre appareil.',
        'placeholder'    => 'XXXX-XXXX',
        'deny'           => 'Refuser',
        'approve'        => 'Approuver',
        // Comme en anglais, ne distingue pas invalide / expiré / déjà utilisé :
        // le préciser donnerait à un attaquant un oracle pour énumérer les
        // codes valides.
        'invalid'        => 'Ce code est invalide, expiré ou déjà utilisé.',
        'approved'       => 'Appareil approuvé. Vous pouvez revenir à votre appareil.',
        'denied'         => 'Appareil refusé.',
        'login_required' => 'Connexion requise.',
    ],

    // --- Interface d'administration -----------------------------------------
    'admin' => [
        'title'            => 'Administration OAuth2',
        'tab_clients'      => 'Clients',
        'tab_scopes'       => 'Portées',
        'tab_grants'       => 'Autorisations',
        'clients_intro'    => 'Tous les clients OAuth enregistrés dans ce locataire.',
        'scopes_title'     => 'Catalogue des portées',
        'grants_title'     => 'Autorisations accordées',
        'grants_intro'     => 'Toutes les autorisations actives, tous utilisateurs confondus.',
        'loading'          => 'Chargement…',
        'col_name'         => 'Nom',
        'col_owner'        => 'Propriétaire',
        'col_type'         => 'Type',
        'col_scopes'       => 'Portées',
        'col_status'       => 'Statut',
        'empty_clients'    => 'Aucun client pour le moment.',
        'empty_scopes'     => 'Aucune portée enregistrée.',
        'empty_grants'     => 'Aucune autorisation active.',
        'register_title'   => 'Enregistrer un client OAuth',
        'field_scopes'     => 'Portées (séparées par des espaces)',
        'scopes_hint'      => 'Chaque portée doit exister dans le catalogue.',
        'field_grants'     => 'Types d\'autorisation',
        'field_public'     => 'Client public (PKCE) — désactivé = confidentiel',
        'cancel'           => 'Annuler',
        'create'           => 'Créer le client',
    ],
];
