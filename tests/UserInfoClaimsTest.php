<?php

declare(strict_types=1);

namespace Tests\Unit\Plugins\OAuth2;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Plugins\OAuth2\Infrastructure\Identity\SubjectUserInfoProvider;
use Plugins\OAuth2\Infrastructure\Identity\UserServiceUserInfoProvider;
use Plugins\User\API\Contracts\UserServiceContract;
use Plugins\User\API\DTOs\ListUsersQuery;
use Plugins\User\API\DTOs\RegisterUserDTO;
use Plugins\User\API\DTOs\UpdateUserDTO;
use Plugins\User\API\DTOs\UserDTO;
use Plugins\User\API\DTOs\UserPage;
use Plugins\User\API\DTOs\VerifyEmailDTO;
use Plugins\User\API\DTOs\VerifyEmailResult;

#[CoversClass(UserServiceUserInfoProvider::class)]
#[CoversClass(SubjectUserInfoProvider::class)]
final class UserInfoClaimsTest extends TestCase
{
    /**
     * Records how find() was called, because two of its arguments are load-bearing
     * and neither is visible in the emitted claims:
     *
     *   isAuth: true          — find() otherwise runs requireSelfOrPermission()
     *                           against the CURRENT Identity. There is none at
     *                           /oauth/token (the client authenticates with PKCE
     *                           or a secret), so a false here throws and a valid
     *                           token request fails.
     *   checkMembership: false — true returns null for a user with no active seat
     *                           in the current tenant, silently stripping the
     *                           claims from an otherwise valid token.
     */
    private function users(?UserDTO $user, bool $throw = false): UserServiceContract
    {
        return new class ($user, $throw) implements UserServiceContract {
            /** @var list<array{string, bool, bool}> */
            public array $calls = [];

            public function __construct(private readonly ?UserDTO $user, private readonly bool $throw)
            {
            }

            public function find(string $id, bool $checkMembership = false, bool $isAuth = false): ?UserDTO
            {
                $this->calls[] = [$id, $checkMembership, $isAuth];

                if ($this->throw) {
                    throw new \RuntimeException('identity store unreachable');
                }

                return $this->user;
            }

            // ── unused by this collaborator ──────────────────────────────────
            public function list(ListUsersQuery $query): UserPage
            {
                throw new \LogicException('not used');
            }

            public function register(RegisterUserDTO $dto): UserDTO
            {
                throw new \LogicException('not used');
            }

            public function registerPublic(RegisterUserDTO $dto): string
            {
                throw new \LogicException('not used');
            }

            public function verifyEmailByToken(string $token): VerifyEmailResult
            {
                throw new \LogicException('not used');
            }

            public function resendVerification(string $email): ?string
            {
                throw new \LogicException('not used');
            }

            public function findByIdentifier(string $identifier, bool $checkMembership = false): ?UserDTO
            {
                throw new \LogicException('not used');
            }

            public function resetPassword(string $userId, string $newPassword): bool
            {
                throw new \LogicException('not used');
            }

            public function update(string $id, UpdateUserDTO $dto): ?UserDTO
            {
                throw new \LogicException('not used');
            }

            public function verifyEmail(string $id, VerifyEmailDTO $dto): ?UserDTO
            {
                throw new \LogicException('not used');
            }

            public function verifyCredentials(string $identifier, string $password): ?UserDTO
            {
                throw new \LogicException('not used');
            }

            public function credentialsAwaitingVerification(string $identifier, string $password): ?string
            {
                throw new \LogicException('not used');
            }

            public function findByRememberToken(string $token): ?UserDTO
            {
                throw new \LogicException('not used');
            }

            public function cycleRememberToken(string $userId, bool $checkMembership = false): string
            {
                throw new \LogicException('not used');
            }

            public function clearRememberToken(string $userId, bool $checkMembership = false): void
            {
                throw new \LogicException('not used');
            }

            public function lockoutStatus(string $userId): bool
            {
                throw new \LogicException('not used');
            }

            public function clearLockout(string $userId): bool
            {
                throw new \LogicException('not used');
            }

            public function delete(string $id, bool $checkMembership = false): bool
            {
                throw new \LogicException('not used');
            }
        };
    }

    private function user(string $fullName = 'Ada Lovelace', ?string $avatar = 'https://cdn/a.png'): UserDTO
    {
        return new UserDTO(
            id: 'u-1',
            username: 'ada',
            email: 'ada@example.com',
            emailVerified: true,
            createdAt: '2026-01-01T00:00:00+00:00',
            fullName: $fullName,
            avatarUrl: $avatar,
        );
    }

    public function test_profile_and_email_scopes_yield_their_standard_claims(): void
    {
        $claims = (new UserServiceUserInfoProvider($this->users($this->user())))
            ->claims('u-1', ['openid', 'profile', 'email']);

        self::assertSame([
            'sub'                => 'u-1',
            'name'               => 'Ada Lovelace',
            'preferred_username' => 'ada',
            'picture'            => 'https://cdn/a.png',
            'email'              => 'ada@example.com',
            'email_verified'     => true,
        ], $claims);
    }

    public function test_profile_scope_alone_does_not_leak_the_email(): void
    {
        $claims = (new UserServiceUserInfoProvider($this->users($this->user())))
            ->claims('u-1', ['openid', 'profile']);

        self::assertArrayNotHasKey('email', $claims);
        self::assertArrayNotHasKey('email_verified', $claims);
        self::assertSame('Ada Lovelace', $claims['name']);
    }

    public function test_email_scope_alone_does_not_leak_the_profile(): void
    {
        $claims = (new UserServiceUserInfoProvider($this->users($this->user())))
            ->claims('u-1', ['openid', 'email']);

        self::assertSame(['sub' => 'u-1', 'email' => 'ada@example.com', 'email_verified' => true], $claims);
    }

    public function test_openid_alone_returns_only_the_subject_and_never_queries(): void
    {
        $users  = $this->users($this->user());
        $claims = (new UserServiceUserInfoProvider($users))->claims('u-1', ['openid']);

        self::assertSame(['sub' => 'u-1'], $claims);
        // No scope needs identity data, so the lookup must be skipped entirely
        // rather than performed and discarded.
        self::assertSame([], $users->calls);
    }

    public function test_absent_profile_values_are_omitted_not_sent_empty(): void
    {
        $claims = (new UserServiceUserInfoProvider($this->users($this->user(fullName: '', avatar: null))))
            ->claims('u-1', ['openid', 'profile']);

        // A blank name renders as a blank display name in a client, which is
        // worse than no name at all — the client can fall back only if the claim
        // is missing.
        self::assertArrayNotHasKey('name', $claims);
        self::assertArrayNotHasKey('picture', $claims);
        self::assertSame('ada', $claims['preferred_username']);
    }

    public function test_email_verified_false_is_still_reported(): void
    {
        $user = new UserDTO(
            id: 'u-1',
            username: 'ada',
            email: 'ada@example.com',
            emailVerified: false,
            createdAt: '2026-01-01T00:00:00+00:00',
        );

        $claims = (new UserServiceUserInfoProvider($this->users($user)))->claims('u-1', ['email']);

        // false is a VALUE, not an absence: a relying party uses it to refuse the
        // address as an account key, so it must never be filtered out.
        self::assertArrayHasKey('email_verified', $claims);
        self::assertFalse($claims['email_verified']);
    }

    public function test_lookup_bypasses_the_self_or_permission_gate_and_the_membership_check(): void
    {
        $users = $this->users($this->user());
        (new UserServiceUserInfoProvider($users))->claims('u-1', ['profile']);

        self::assertSame([['u-1', false, true]], $users->calls, 'find($id, checkMembership: false, isAuth: true)');
    }

    public function test_unknown_user_degrades_to_the_subject(): void
    {
        $claims = (new UserServiceUserInfoProvider($this->users(null)))->claims('u-1', ['profile', 'email']);

        self::assertSame(['sub' => 'u-1'], $claims);
    }

    public function test_a_failing_identity_store_never_costs_the_caller_their_token(): void
    {
        $claims = (new UserServiceUserInfoProvider($this->users(null, throw: true)))
            ->claims('u-1', ['profile', 'email']);

        self::assertSame(['sub' => 'u-1'], $claims);
    }

    public function test_default_provider_still_returns_only_the_subject(): void
    {
        self::assertSame(['sub' => 'u-1'], (new SubjectUserInfoProvider())->claims('u-1', ['profile', 'email']));
    }
}
