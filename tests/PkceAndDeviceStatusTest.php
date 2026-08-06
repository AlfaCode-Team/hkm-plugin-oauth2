<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\OAuth2;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\OAuth2\Application\Services\AuthorizationService;
use Plugins\OAuth2\Application\Services\ScopeValidator;
use Plugins\OAuth2\Domain\Entities\Client;
use Plugins\OAuth2\Domain\Entities\DeviceCode;
use Plugins\OAuth2\Domain\ValueObjects\Pkce;
use Plugins\OAuth2\Domain\Exceptions\OAuthException;

// The in-memory stores live at the bottom of OAuth2FlowTest.php rather than in
// their own files, so they are only defined once that file has been loaded.
// Requiring it keeps a single copy of the fakes instead of a second, divergent set.
require_once __DIR__ . '/OAuth2FlowTest.php';

/**
 * Regression cover for S-16 (public clients could be downgraded to PKCE
 * "plain", which protects nothing) and S-32k (a redeemed device code was
 * recorded as DENIED).
 */
#[CoversClass(AuthorizationService::class)]
#[CoversClass(DeviceCode::class)]
final class PkceAndDeviceStatusTest extends TestCase
{
    private const REDIRECT = 'https://app.test/cb';

    private function service(): AuthorizationService
    {
        $clients = new InMemoryClientStore([
            Client::of('public-spa', 'SPA', null, [self::REDIRECT], ['authorization_code'], ['profile'], false),
            Client::of('web-app', 'Web', 'h:s', [self::REDIRECT], ['authorization_code'], ['profile'], true),
        ]);

        return new AuthorizationService(
            $clients,
            new InMemoryAuthCodeStore(),
            new ScopeValidator(new InMemoryScopeStore(['profile'])),
            60,
        );
    }

    /** @return array<string,string> */
    private function params(string $clientId, array $overrides = []): array
    {
        return array_merge([
            'client_id'     => $clientId,
            'redirect_uri'  => self::REDIRECT,
            'response_type' => 'code',
            'scope'         => 'profile',
            'state'         => 'xyz',
            'code_challenge' => str_repeat('a', 43),
        ], $overrides);
    }

    // ── S-16 ────────────────────────────────────────────────────────────────

    public function test_a_public_client_may_not_use_plain(): void
    {
        // plain makes the challenge identical to the verifier, and both cross
        // the front channel — PKCE then protects nothing, and a public client
        // has no secret to fall back on.
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessageMatches('/must use code_challenge_method=S256/');

        $this->service()->validate($this->params('public-spa', ['code_challenge_method' => 'plain']));
    }

    public function test_a_public_client_may_not_omit_the_method(): void
    {
        // RFC 7636 defaults an ABSENT method to plain, so omission was a silent
        // downgrade of a client that intended S256.
        $this->expectException(OAuthException::class);
        $this->expectExceptionMessageMatches('/must use code_challenge_method=S256/');

        $this->service()->validate($this->params('public-spa'));
    }

    public function test_a_public_client_using_s256_is_accepted(): void
    {
        $req = $this->service()->validate(
            $this->params('public-spa', ['code_challenge_method' => Pkce::METHOD_S256]),
        );

        self::assertSame(Pkce::METHOD_S256, $req->codeChallengeMethod);
    }

    public function test_a_confidential_client_may_still_use_plain(): void
    {
        // It authenticates with a secret at the token endpoint, so PKCE is
        // defence in depth rather than the only control.
        $req = $this->service()->validate($this->params('web-app', ['code_challenge_method' => 'plain']));

        self::assertSame(Pkce::METHOD_PLAIN, $req->codeChallengeMethod);
    }

    // ── S-32k ───────────────────────────────────────────────────────────────

    public function test_redeemed_is_distinct_from_denied(): void
    {
        // Redeeming used to write DENIED, so a device polling once more after a
        // SUCCESSFUL exchange was told access_denied.
        self::assertNotSame(DeviceCode::DENIED, DeviceCode::REDEEMED);
        self::assertSame('redeemed', DeviceCode::REDEEMED);
        // Must fit the existing varchar(16) column — no migration required.
        self::assertLessThanOrEqual(16, \strlen(DeviceCode::REDEEMED));
    }
}
