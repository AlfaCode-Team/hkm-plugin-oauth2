<?php

declare(strict_types=1);

namespace Plugins\OAuth2\Domain\ValueObjects;

/**
 * RedirectUri — what a client may register as a redirect target
 * (RFC 6749 §3.1.2, RFC 8252 §7.1 and §8.3).
 *
 * Registration used to accept any string that survived `is_string`, so a client
 * could be stored with `javascript:` or `data:` in its redirect list. Those are
 * inert in a `Location` header, which is why this is hardening rather than a
 * live hole — but registration is the only place the value is ever inspected,
 * and a URI that could never legitimately receive an authorization code should
 * be refused when it is written, not tolerated because the one consumer that
 * exists today happens to be safe.
 *
 * What is accepted:
 *   - `https://…`                 — anywhere
 *   - `http://…`                  — LOOPBACK hosts only (RFC 8252 §8.3), the
 *                                   sanctioned pattern for a native app's
 *                                   ephemeral local listener
 *   - `com.example.app:/cb`,      — a private-use scheme belonging to a native
 *     `myapp://cb`                  app (RFC 8252 §7.1). The OS routes these,
 *                                   not a browser, so the app owns the risk
 *
 * What is refused, and why:
 *   - a scheme a BROWSER would act on as content (`javascript:`, `data:`,
 *     `vbscript:`, `blob:`, `file:`, `about:`, `view-source:`) — the only
 *     schemes whose whole purpose is to execute or expose something locally
 *   - plain `http` to any non-loopback host — the code would cross the network
 *     in the clear
 *   - a fragment: RFC 6749 §3.1.2 says the endpoint URI MUST NOT include one,
 *     and the server appends `?code=…` assuming there is nothing after it
 *   - a relative URI, or anything carrying control characters or whitespace
 *     ANYWHERE, edges included — that is what makes response-header splitting
 *     possible downstream, and a byte-exact match impossible for the client
 *
 * Deliberately NOT enforced: reverse-DNS shape on a private-use scheme. RFC 8252
 * §7.1 recommends it, but `myapp://` is widespread in shipped apps and refusing
 * it would reject working integrations to enforce a SHOULD.
 */
final class RedirectUri
{
    /** Schemes a browser interprets as content rather than a location. */
    private const FORBIDDEN_SCHEMES = [
        'javascript', 'data', 'vbscript', 'blob', 'file', 'about', 'view-source',
    ];

    /** Hosts that may use plain http, per RFC 8252 §8.3. */
    private const LOOPBACK = ['localhost', '127.0.0.1', '[::1]'];

    /** Guards against a registration payload used as a storage channel. */
    private const MAX_LENGTH = 2000;

    public static function isValid(string $uri): bool
    {
        if ($uri === '' || strlen($uri) > self::MAX_LENGTH) {
            return false;
        }

        // Checked on the RAW argument, deliberately UNTRIMMED. The caller stores
        // exactly the string it validates, and PHP's trim() strips NUL along with
        // whitespace — so trimming first would clear `…/cb\0` here and then write
        // the NUL to the database anyway. Refusing a stray space is also the right
        // outcome on its own: redirect matching is byte-exact, so a URI with an
        // invisible edge character can never be matched by the client that sent it.
        if (preg_match('/[\x00-\x20\x7F]/', $uri) === 1) {
            return false;
        }

        // Checked on the RAW string as well as the parsed parts: parse_url only
        // reports a fragment when there is something after the '#'.
        if (str_contains($uri, '#')) {
            return false;
        }

        $parts = parse_url($uri);
        if ($parts === false || !isset($parts['scheme'])) {
            return false;
        }

        $scheme = strtolower($parts['scheme']);
        if (in_array($scheme, self::FORBIDDEN_SCHEMES, true)) {
            return false;
        }

        if ($scheme === 'https') {
            return ($parts['host'] ?? '') !== '';
        }

        if ($scheme === 'http') {
            return in_array(strtolower((string) ($parts['host'] ?? '')), self::LOOPBACK, true);
        }

        // A private-use scheme for a native app. It still has to be a real URI
        // scheme token, so a bare word with punctuation cannot slip through.
        return preg_match('/^[a-z][a-z0-9+.\-]*$/', $scheme) === 1;
    }

    /**
     * The entries that are NOT acceptable — empty means the whole list is fine.
     * Callers report these back to the registrant verbatim.
     *
     * @param  list<string> $uris
     * @return list<string>
     */
    public static function invalidIn(array $uris): array
    {
        return array_values(array_filter(
            $uris,
            static fn (string $uri): bool => !self::isValid($uri),
        ));
    }
}
