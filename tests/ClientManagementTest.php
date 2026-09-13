<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\OAuth2;

use AlfacodeTeam\PhpServicePlatform\Kernel\Http\Request;
use AlfacodeTeam\PhpServicePlatform\Kernel\Security\Identity;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\OAuth2\Application\Ports\ClientStore;
use Plugins\OAuth2\Domain\Entities\Client;
use Plugins\OAuth2\Infrastructure\Http\Controllers\ClientController;
use Tests\Unit\Plugins\User\Support\FakeHasher;

#[CoversClass(ClientController::class)]
final class ClientManagementTest extends TestCase
{
    private function store(): ClientStore
    {
        return new class implements ClientStore {
            /** @var array<string,Client> */
            public array $byId = [];
            public function find(string $clientId): ?Client { return $this->byId[$clientId] ?? null; }
            public function create(string $id, string $name, ?string $secretHash, array $redirectUris, array $grantTypes, array $scopes, bool $confidential, ?string $ownerId = null): void
            {
                $this->byId[$id] = Client::of($id, $name, $secretHash, $redirectUris, $grantTypes, $scopes, $confidential, false, $ownerId);
            }
            public function all(): array { return array_values($this->byId); }
            public function findByOwner(string $ownerId): array
            {
                return array_values(array_filter($this->byId, static fn(Client $c) => $c->ownerId() === $ownerId));
            }
            public function updateDetails(string $id, string $name, array $redirectUris, array $scopes): bool
            {
                $c = $this->byId[$id] ?? null;
                if ($c === null) { return false; }
                $this->byId[$id] = Client::of($c->id, $name, $c->secretHash, $redirectUris, $c->grantTypes, $scopes, $c->confidential, $c->revoked, $c->ownerId());
                return true;
            }
            public function revoke(string $id): bool
            {
                $c = $this->byId[$id] ?? null;
                if ($c === null) { return false; }
                $this->byId[$id] = Client::of($c->id, $c->name, $c->secretHash, $c->redirectUris, $c->grantTypes, $c->scopes, $c->confidential, true, $c->ownerId());
                return true;
            }
            public function updateSecret(string $id, string $secretHash): bool { return false; }
        };
    }

    private function controller(ClientStore $store, Identity $identity, array $body = []): ClientController
    {
        $request = Request::build(method: 'POST', path: '/oauth/clients', body: $body)->withIdentity($identity);

        return (new ClientController($store, new FakeHasher()))->setRequest($request);
    }

    public function test_store_creates_owner_scoped_confidential_client_with_secret(): void
    {
        $store = $this->store();
        $response = $this->controller($store, Identity::asUser('u1', ''), ['name' => 'My App'])->store();

        self::assertSame(201, $response->getStatusCode());
        $client = $store->all()[0];
        self::assertSame('u1', $client->ownerId());
        self::assertFalse($client->isPublic());          // confidential by default
        self::assertNotEmpty($store->findByOwner('u1'));
    }

    public function test_for_user_lists_only_my_clients(): void
    {
        $store = $this->store();
        $this->controller($store, Identity::asUser('u1', ''), ['name' => 'Mine'])->store();
        $this->controller($store, Identity::asUser('u2', ''), ['name' => 'Theirs'])->store();

        $response = $this->controller($store, Identity::asUser('u1', ''))->forUser();

        self::assertSame(200, $response->getStatusCode());
        self::assertCount(1, $store->findByOwner('u1'));
    }

    public function test_update_and_destroy_enforce_ownership(): void
    {
        $store = $this->store();
        $store->create('c-other', 'Theirs', null, [], [], [], true, 'u2');

        $ctrl = $this->controller($store, Identity::asUser('u1', ''), ['name' => 'Hijack']);

        self::assertSame(404, $ctrl->update('c-other')->getStatusCode());
        self::assertSame(404, $ctrl->destroy('c-other')->getStatusCode());
        self::assertFalse($store->find('c-other')->revoked); // untouched
    }

    public function test_store_refuses_a_redirect_uri_that_could_never_receive_a_code(): void
    {
        $store = $this->store();

        $response = $this->controller($store, Identity::asUser('u1', ''), [
            'name'          => 'Sketchy',
            'redirect_uris' => ['https://ok.example.com/cb', 'javascript:alert(1)'],
        ])->store();

        self::assertSame(422, $response->getStatusCode());
        $body = json_decode($response->getContent(), true);
        // The offending entry is named, so the registrant knows which of the two to fix.
        self::assertStringContainsString('javascript:alert(1)', $body['error']['fields']['redirect_uris']);
        // And nothing was written.
        self::assertSame([], $store->all());
    }

    public function test_store_accepts_the_redirect_shapes_a_real_client_uses(): void
    {
        $store = $this->store();

        $response = $this->controller($store, Identity::asUser('u1', ''), [
            'name'          => 'Legit',
            'redirect_uris' => ['https://app.example.com/cb', 'http://127.0.0.1:8765/cb', 'com.example.app:/cb'],
        ])->store();

        self::assertSame(201, $response->getStatusCode());
        self::assertCount(3, $store->all()[0]->redirectUris);
    }

    public function test_guest_cannot_manage_clients(): void
    {
        self::assertSame(401, $this->controller($this->store(), Identity::guest())->forUser()->getStatusCode());
    }
}
