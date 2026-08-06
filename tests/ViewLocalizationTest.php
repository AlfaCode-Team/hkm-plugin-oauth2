<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\OAuth2;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use Plugins\I18n\Support\Lang;
use Plugins\I18n\Translator;

/**
 * The OAuth screens must actually render translated copy.
 *
 * A catalogue existing is not the same as a view using it: a template still
 * holding a hard-coded sentence, or calling a key nobody defined, passes every
 * catalogue test and still serves English to a French user. These render the
 * real template files against a real Translator.
 *
 * The consent screen gets the most attention here because it is the screen
 * where a user grants an application access to their account — if any surface
 * in this plugin must be unambiguous in the reader's own language, it is that
 * one.
 */
#[CoversNothing]
final class ViewLocalizationTest extends TestCase
{
    protected function tearDown(): void
    {
        Lang::clear();
    }

    /**
     * Wire the Translator the way the boot manifest wires this plugin:
     * module.json declares the catalogue with "global": false, so the `oauth2`
     * NAMESPACE is the only route in. Registering it as a global path instead
     * would resolve nothing and every key would render as itself.
     */
    private function bindLocale(string $locale): void
    {
        Lang::bind(new Translator(
            directory:  [],
            locale:     $locale,
            fallback:   'en',
            namespaces: ['oauth2' => [dirname(__DIR__) . '/resources/lang']],
        ));
    }

    /** @param array<string,mixed> $data */
    private function render(string $view, array $data): string
    {
        $file = dirname(__DIR__) . '/resources/views/' . $view . '.php';
        self::assertFileExists($file);

        extract($data, EXTR_SKIP);
        ob_start();
        include $file;

        return (string) ob_get_clean();
    }

    /**
     * admin.php documents @var $userId and $email; omitting them renders the
     * page with undefined-variable warnings rather than a clean failure.
     *
     * @return array<string,mixed>
     */
    private function adminData(): array
    {
        return ['userId' => 'user-1', 'email' => 'admin@example.com'];
    }

    /** @return array<string,mixed> */
    private function consentData(): array
    {
        return [
            'csrf'       => 'tok',
            'clientName' => 'Acme App',
            'scopes'     => ['read profile', 'write invoices'],
            'authzId'    => 'authz-1',
        ];
    }

    // --- Consent --------------------------------------------------------------

    public function test_consent_renders_english(): void
    {
        $this->bindLocale('en');
        $html = $this->render('consent', $this->consentData());

        $this->assertStringContainsString('Authorize Acme App', $html);
        $this->assertStringContainsString('is requesting access to your account', $html);
        $this->assertStringContainsString('lang="en"', $html);
    }

    public function test_consent_renders_french(): void
    {
        $this->bindLocale('fr');
        $html = $this->render('consent', $this->consentData());

        $this->assertStringContainsString('Autoriser Acme App', $html);
        $this->assertStringContainsString('demande l\'accès à votre compte', $html);
        $this->assertStringNotContainsString('is requesting access', $html);
        $this->assertStringContainsString('lang="fr"', $html);
    }

    /**
     * The client name and the scopes are what the user is actually consenting
     * to. Localising the surrounding copy must never drop them.
     */
    public function test_consent_still_shows_the_client_and_its_scopes(): void
    {
        $this->bindLocale('fr');
        $html = $this->render('consent', $this->consentData());

        $this->assertStringContainsString('Acme App', $html);
        $this->assertStringContainsString('read profile', $html);
        $this->assertStringContainsString('write invoices', $html);
    }

    /** The approve/deny buttons must keep their machine values, not their labels. */
    public function test_consent_buttons_keep_their_submitted_values(): void
    {
        $this->bindLocale('fr');
        $html = $this->render('consent', $this->consentData());

        // If a translation ever replaced the value attribute the form would
        // submit French words the controller does not recognise.
        $this->assertStringContainsString('value="approve"', $html);
        $this->assertStringContainsString('value="deny"', $html);
        $this->assertStringContainsString('Autoriser<', $html);
        $this->assertStringContainsString('Refuser<', $html);
    }

    public function test_consent_omits_the_scope_list_when_there_are_none(): void
    {
        $this->bindLocale('fr');
        $html = $this->render('consent', ['csrf' => 't', 'clientName' => 'A', 'scopes' => [], 'authzId' => 'x']);

        $this->assertStringNotContainsString('Cette application pourra', $html);
    }

    // --- Device ---------------------------------------------------------------

    public function test_device_renders_french(): void
    {
        $this->bindLocale('fr');
        $html = $this->render('device', ['csrf' => 't', 'userCode' => 'ABCD-1234', 'message' => '']);

        $this->assertStringContainsString('Connecter un appareil', $html);
        $this->assertStringContainsString('Saisissez le code', $html);
        $this->assertStringContainsString('ABCD-1234', $html, 'the entered code must survive a re-render');
    }

    public function test_device_message_is_shown_when_present(): void
    {
        $this->bindLocale('fr');
        $html = $this->render('device', ['csrf' => 't', 'userCode' => '', 'message' => 'Appareil refusé.']);

        $this->assertStringContainsString('Appareil refusé.', $html);
    }

    // --- Admin ----------------------------------------------------------------

    public function test_admin_renders_french(): void
    {
        $this->bindLocale('fr');
        $html = $this->render('admin', $this->adminData());

        $this->assertStringContainsString('Administration OAuth2', $html);
        $this->assertStringContainsString('Catalogue des portées', $html);
        $this->assertStringNotContainsString('OAuth2 Admin<', $html);
    }

    // --- No leakage -----------------------------------------------------------

    public function test_no_english_copy_survives_a_french_render(): void
    {
        $this->bindLocale('fr');

        $html = $this->render('consent', $this->consentData())
            . $this->render('device', ['csrf' => 't', 'userCode' => '', 'message' => ''])
            . $this->render('admin', $this->adminData());

        foreach ([
            'is requesting access',
            'It will be able to',
            'Enter the code shown',
            'Connect a device',
            'Every OAuth client registered',
            'No clients yet',
        ] as $english) {
            $this->assertStringNotContainsString($english, $html, "untranslated: {$english}");
        }
    }

    /**
     * An unresolved key renders as the key itself, which would put
     * "oauth2::oauth.consent.title" in front of a user mid-authorization.
     */
    public function test_no_raw_translation_keys_leak_into_the_output(): void
    {
        foreach (['en', 'fr'] as $locale) {
            $this->bindLocale($locale);

            $html = $this->render('consent', $this->consentData())
                . $this->render('device', ['csrf' => 't', 'userCode' => '', 'message' => ''])
                . $this->render('admin', $this->adminData());

            $this->assertStringNotContainsString('oauth2::', $html, "[{$locale}] an unresolved key reached the output");
        }
    }
}
