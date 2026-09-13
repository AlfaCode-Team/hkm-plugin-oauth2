<?php

declare(strict_types=1);

namespace Plugins\OAuth2\Application\Services;

use AlfacodeTeam\PhpServicePlatform\Kernel\Ports\CachePort;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Plugins\OAuth2\Application\Ports\RefreshTokenStore;

/**
 * IntrospectionService — RFC 7662 token introspection + RFC 7009 revocation.
 *
 * Access tokens are self-describing JWTs, so introspection verifies the
 * signature/expiry locally. Refresh tokens are opaque and looked up by hash.
 * Returns the RFC 7662 response shape; an inactive/invalid token always returns
 * `{"active": false}` with no other detail (no information leak).
 */
final class IntrospectionService
{
    /** Mirrors Plugins\Auth\Security\JwtAuthLayer's deny-list key (kept inline to avoid coupling). */
    private const JWT_REVOCATION_PREFIX = 'auth:jwt:revoked:';

    public function __construct(
        private readonly RefreshTokenStore $refreshTokens,
        private readonly TokenIssuer $issuer,
        private readonly string $verifyKey,  // HS secret or PEM public key
        private readonly string $algo,
        private readonly ?CachePort $revocations = null,
    ) {
    }

    /**
     * @param  string $callerClientId the CONFIDENTIAL client that authenticated
     *                to this endpoint. A token issued to any other client is
     *                reported inactive — RFC 7662 introspection is not a lookup
     *                service for tokens the caller was never given.
     * @return array<string,mixed>
     */
    public function introspect(string $token, string $callerClientId): array
    {
        if ($token === '') {
            return ['active' => false];
        }

        // 1. Try as a JWT access token.
        try {
            $claims = (array) JWT::decode($token, new Key($this->verifyKey, $this->algo));

            // A signature only proves the token was MINTED by us. Revocation
            // happens after minting, so the deny-list has to be consulted
            // separately — without this, a token the user explicitly revoked
            // reported active for its whole natural lifetime, and every resource
            // server that validates by introspection (rather than by verifying
            // the signature itself, where JwtAuthLayer already checks the list)
            // kept accepting it.
            if ($this->isDenyListed((string) ($claims['jti'] ?? ''))) {
                return ['active' => false];
            }

            if (!self::sameClient((string) ($claims['client_id'] ?? ''), $callerClientId)) {
                return ['active' => false];
            }

            return [
                'active'     => true,
                'token_type' => 'access_token',
                'scope'      => $claims['scope'] ?? '',
                'client_id'  => $claims['client_id'] ?? null,
                'sub'        => $claims['sub'] ?? null,
                'exp'        => $claims['exp'] ?? null,
                'iat'        => $claims['iat'] ?? null,
                'iss'        => $claims['iss'] ?? null,
                'aud'        => $claims['aud'] ?? null,
                'jti'        => $claims['jti'] ?? null,
            ];
        } catch (\Throwable) {
            // not a (valid) JWT — fall through to opaque refresh lookup
        }

        // 2. Try as an opaque refresh token.
        $record = $this->refreshTokens->findByHash($this->issuer->hash($token));
        if ($record !== null
            && !$record->revoked
            && !$record->isExpired()
            && self::sameClient((string) $record->clientId, $callerClientId)) {
            return [
                'active'     => true,
                'token_type' => 'refresh_token',
                'scope'      => implode(' ', $record->scopes),
                'client_id'  => $record->clientId,
                'sub'        => $record->userId,
                'exp'        => $record->expiresAt->getTimestamp(),
            ];
        }

        return ['active' => false];
    }

    /**
     * RFC 7009 revocation. Handles BOTH token types:
     *   - opaque refresh token → revoke the whole rotation family;
     *   - JWT access token     → deny-list its `jti` (same list the platform
     *     JwtAuthLayer consults), so it stops authenticating before its natural
     *     expiry.
     * Per the RFC, an unknown/unsupported token still returns success.
     *
     * @param string $callerClientId the client that authenticated to this
     *               endpoint. RFC 7009 §2.1 requires the server to verify the
     *               token was issued to it; a token belonging to someone else is
     *               left untouched, and — per the same section — the caller is
     *               still told nothing, so this cannot be used to probe which
     *               tokens exist.
     */
    public function revoke(string $token, string $callerClientId): void
    {
        if ($token === '') {
            return;
        }

        // Access token (JWT): deny-list the jti until it would have expired.
        try {
            $claims = (array) JWT::decode($token, new Key($this->verifyKey, $this->algo));

            if (!self::sameClient((string) ($claims['client_id'] ?? ''), $callerClientId)) {
                return;
            }

            $jti = (string) ($claims['jti'] ?? '');
            if ($jti !== '' && $this->revocations !== null) {
                $ttl = max(1, (int) ($claims['exp'] ?? 0) - time());
                $this->revocations->set(self::JWT_REVOCATION_PREFIX . $jti, 1, $ttl);
            }

            return;
        } catch (\Throwable) {
            // not a JWT — treat as an opaque refresh token below
        }

        $record = $this->refreshTokens->findByHash($this->issuer->hash($token));
        if ($record !== null && self::sameClient((string) $record->clientId, $callerClientId)) {
            $this->refreshTokens->revokeFamily($record->familyId);
        }
    }

    /**
     * Is this token id on the revocation deny-list?
     *
     * FAILS OPEN on a cache outage, deliberately matching JwtAuthLayer: the two
     * consult the same list, and if they disagreed about an unreachable cache a
     * token would authenticate on one path and read as dead on the other. The
     * token is cryptographically valid either way; a cache being down is not
     * evidence that it was revoked.
     */
    private function isDenyListed(string $jti): bool
    {
        if ($jti === '' || $this->revocations === null) {
            return false;
        }

        try {
            return $this->revocations->has(self::JWT_REVOCATION_PREFIX . $jti);
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Constant-time owner check. An EMPTY caller id never matches, so a caller
     * that reaches these methods without authenticating cannot pass by handing
     * over a token whose own client_id claim is missing.
     */
    private static function sameClient(string $tokenClientId, string $callerClientId): bool
    {
        return $tokenClientId !== ''
            && $callerClientId !== ''
            && hash_equals($tokenClientId, $callerClientId);
    }
}
