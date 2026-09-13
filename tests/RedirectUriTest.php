<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\OAuth2;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Plugins\OAuth2\Domain\ValueObjects\RedirectUri;

/**
 * Registration is the ONLY place a redirect URI is ever inspected — once stored,
 * it is matched byte-for-byte and handed straight to a Location header. These
 * cases pin what may be written.
 */
final class RedirectUriTest extends TestCase
{
    /** @return iterable<string, array{0:string}> */
    public static function acceptable(): iterable
    {
        yield 'https'                => ['https://app.example.com/callback'];
        yield 'https with query'     => ['https://app.example.com/cb?tenant=acme'];
        yield 'https with port'      => ['https://app.example.com:8443/cb'];
        // RFC 8252 §8.3 — a native app's ephemeral loopback listener.
        yield 'http on localhost'    => ['http://localhost:53129/cb'];
        yield 'http on 127.0.0.1'    => ['http://127.0.0.1:53129/cb'];
        yield 'http on ipv6 loopback'=> ['http://[::1]:53129/cb'];
        // RFC 8252 §7.1 — private-use schemes, both shapes real apps ship.
        yield 'reverse-dns scheme'   => ['com.example.app:/oauth2redirect/callback'];
        yield 'short custom scheme'  => ['myapp://callback'];
    }

    /** @return iterable<string, array{0:string}> */
    public static function refused(): iterable
    {
        // The finding: registration accepted any string that was a string.
        yield 'javascript'        => ['javascript:alert(document.cookie)'];
        yield 'data'              => ['data:text/html;base64,PHNjcmlwdD4='];
        yield 'vbscript'          => ['vbscript:msgbox(1)'];
        yield 'file'              => ['file:///etc/passwd'];
        yield 'blob'              => ['blob:https://a.com/uuid'];
        yield 'about'             => ['about:blank'];
        yield 'view-source'       => ['view-source:https://a.com'];
        // Cleartext to a real host would carry the code across the network.
        yield 'http off-loopback' => ['http://app.example.com/cb'];
        yield 'http lookalike'    => ['http://localhost.evil.com/cb'];
        // RFC 6749 §3.1.2 — the endpoint URI MUST NOT include a fragment, and the
        // server appends ?code=… assuming nothing follows.
        yield 'fragment'          => ['https://app.example.com/cb#x'];
        yield 'bare hash'         => ['https://app.example.com/cb#'];
        // Header-splitting material.
        yield 'newline'           => ["https://app.example.com/cb\nX-Evil: 1"];
        yield 'tab'               => ["https://app.example.com/\tcb"];
        yield 'null byte'         => ["https://app.example.com/cb\0"];
        // Not absolute — nothing to redirect to.
        yield 'relative'          => ['/callback'];
        yield 'scheme only'       => ['https://'];
        yield 'empty'             => [''];
        yield 'whitespace'        => ['   '];
    }

    #[DataProvider('acceptable')]
    public function test_accepts_a_usable_redirect_target(string $uri): void
    {
        self::assertTrue(RedirectUri::isValid($uri), $uri . ' should be registrable');
    }

    #[DataProvider('refused')]
    public function test_refuses_a_target_that_could_never_legitimately_receive_a_code(string $uri): void
    {
        self::assertFalse(RedirectUri::isValid($uri), $uri . ' should be refused');
    }

    public function test_invalid_in_names_only_the_offending_entries(): void
    {
        $bad = RedirectUri::invalidIn([
            'https://good.example.com/cb',
            'javascript:alert(1)',
            'com.example.app:/cb',
            'http://evil.example.com/cb',
        ]);

        // The registrant is told exactly which two to fix, not just "invalid".
        self::assertSame(['javascript:alert(1)', 'http://evil.example.com/cb'], $bad);
    }

    public function test_an_empty_list_is_valid(): void
    {
        // A client_credentials-only client legitimately registers no redirects.
        self::assertSame([], RedirectUri::invalidIn([]));
    }
}
