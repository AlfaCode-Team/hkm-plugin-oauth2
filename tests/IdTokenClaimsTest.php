<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\OAuth2;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\OAuth2\Application\Services\TokenIssuer;

#[CoversClass(TokenIssuer::class)]
final class IdTokenClaimsTest extends TestCase
{
    private function issuer(): TokenIssuer
    {
        return new TokenIssuer('HS256', str_repeat('k', 64), null, 'https://issuer.test', null, 3600);
    }

    /** @return array<string,mixed> */
    private function payload(string $jwt): array
    {
        $part = explode('.', $jwt)[1];

        return (array) json_decode(
            (string) base64_decode(strtr($part, '-_', '+/'), true),
            true,
            flags: JSON_THROW_ON_ERROR,
        );
    }

    public function test_identity_claims_are_embedded_alongside_the_reserved_fields(): void
    {
        $payload = $this->payload($this->issuer()->idToken('u-1', 'c-1', claims: [
            'name'  => 'Ada Lovelace',
            'email' => 'ada@example.com',
        ]));

        self::assertSame('Ada Lovelace', $payload['name']);
        self::assertSame('ada@example.com', $payload['email']);
        self::assertSame('u-1', $payload['sub']);
        self::assertSame('c-1', $payload['aud']);
        self::assertSame('https://issuer.test', $payload['iss']);
    }

    /**
     * The whole point of merging identity claims UNDER the reserved set. A
     * provider that returned an `aud`, `sub`, `exp` or `iss` key — through a bug,
     * or through profile data an attacker controls — would otherwise rewrite the
     * fields that decide who the token is for and when it stops being valid.
     */
    public function test_identity_claims_cannot_overwrite_the_reserved_fields(): void
    {
        $before  = time();
        $payload = $this->payload($this->issuer()->idToken('u-1', 'c-1', 'nonce-1', claims: [
            'sub'   => 'attacker',
            'aud'   => 'other-client',
            'iss'   => 'https://evil.test',
            'exp'   => $before + 999_999_999,
            'iat'   => 0,
            'nonce' => 'replaced',
            'name'  => 'Ada Lovelace',
        ]));

        self::assertSame('u-1', $payload['sub']);
        self::assertSame('c-1', $payload['aud']);
        self::assertSame('https://issuer.test', $payload['iss']);
        self::assertSame('nonce-1', $payload['nonce']);
        self::assertLessThanOrEqual($before + 3600, $payload['exp']);
        self::assertGreaterThanOrEqual($before, $payload['iat']);

        // The non-reserved claim still rides along — the guard is targeted, not
        // a blanket rejection of provider input.
        self::assertSame('Ada Lovelace', $payload['name']);
    }

    public function test_no_claims_yields_the_previous_reserved_only_payload(): void
    {
        $payload = $this->payload($this->issuer()->idToken('u-1', 'c-1'));

        self::assertSame(['iss', 'sub', 'aud', 'iat', 'exp'], array_keys($payload));
    }
}
