<?php

declare(strict_types=1);

namespace Plugins\OAuth2\Infrastructure\Identity;

use Plugins\OAuth2\Application\Ports\UserInfoProvider;
use Plugins\User\API\Contracts\UserServiceContract;

/**
 * UserInfo claims read from the platform's own identity store.
 *
 * This plugin already declares `user.management` in module.json and already
 * resolves {@see UserServiceContract} for the password grant, so the identity
 * data OIDC asks for is available without any project wiring. Before this
 * existed the default {@see SubjectUserInfoProvider} was the only binding, and
 * both /oauth/userinfo and every id_token returned nothing but `sub` — a client
 * that requested `profile email` got exactly what a client that requested
 * neither did, which is not a conformant OIDC response.
 *
 * Claims follow OIDC Core §5.1 (Standard Claims) and are emitted ONLY for the
 * scopes actually granted, per §5.4:
 *
 *   openid   → sub                                   (always; the subject)
 *   profile  → name, preferred_username, picture
 *   email    → email, email_verified
 *
 * Claims are omitted rather than sent empty. A consumer must be able to treat a
 * present claim as a real value; `"name": ""` is worse than no `name` at all,
 * because it renders as a blank display name instead of falling back.
 */
final class UserServiceUserInfoProvider implements UserInfoProvider
{
    public function __construct(private readonly UserServiceContract $users)
    {
    }

    /**
     * @param list<string> $scopes granted scope names, already stripped of the
     *                             `scope:` prefix the Identity carries them under
     * @return array<string,mixed>
     */
    public function claims(string $userId, array $scopes): array
    {
        // `sub` is the one claim that does not depend on a scope or on the
        // lookup succeeding — it is the subject the caller already proved.
        $claims = ['sub' => $userId];

        // Nothing beyond `sub` is being asked for: skip the query entirely.
        if (!in_array('profile', $scopes, true) && !in_array('email', $scopes, true)) {
            return $claims;
        }

        $user = $this->lookup($userId);
        if ($user === null) {
            return $claims;
        }

        if (in_array('profile', $scopes, true)) {
            // `name` comes from the TENANT user_profiles row and is '' until a
            // profile exists; `picture` is null for the same reason. Both are
            // dropped when absent rather than sent hollow.
            if ($user->fullName !== '') {
                $claims['name'] = $user->fullName;
            }
            if ($user->username !== '') {
                $claims['preferred_username'] = $user->username;
            }
            if ($user->avatarUrl !== null && $user->avatarUrl !== '') {
                $claims['picture'] = $user->avatarUrl;
            }
        }

        if (in_array('email', $scopes, true) && $user->email !== '') {
            $claims['email'] = $user->email;
            // Relying parties use this to decide whether the address may be
            // trusted as an account key, so it must always ride along with it.
            $claims['email_verified'] = $user->emailVerified;
        }

        return $claims;
    }

    /**
     * `isAuth: true` is REQUIRED here, and the reason is not obvious.
     *
     * UserService::find() runs requireSelfOrPermission($id, 'user:read-any')
     * unless that flag is set — a check against the CURRENT request's Identity.
     * At /oauth/userinfo an Identity exists (JwtAuthLayer attached it) and the
     * subject is itself, so the gate would pass. But this provider is also used
     * to build the id_token at /oauth/token, which is an UNAUTHENTICATED
     * endpoint: the client authenticates with PKCE or a client secret, and no
     * Identity is ever attached. There the gate throws, and a token request
     * that should have succeeded fails instead.
     *
     * The flag is exactly right for this call: the caller has already
     * established the subject cryptographically (a redeemed authorization code
     * or a verified access token), which is a stronger proof than the
     * self-or-permission check it replaces.
     *
     * `checkMembership: false` because UserInfo is about the GLOBAL identity,
     * not a seat: passing true returns null for a user with no active
     * membership in the current tenant, which would silently strip the claims
     * from an otherwise valid token. The profile (name, avatar) is resolved
     * either way.
     */
    private function lookup(string $userId): ?\Plugins\User\API\DTOs\UserDTO
    {
        try {
            return $this->users->find($userId, checkMembership: false, isAuth: true);
        } catch (\Throwable) {
            // A failed profile lookup must never cost the caller their token or
            // their 200 — degrade to the `sub`-only response the default
            // provider would have given.
            return null;
        }
    }
}
