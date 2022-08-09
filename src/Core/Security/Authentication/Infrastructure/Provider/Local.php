<?php
/*
 * Copyright 2005 - 2022 Centreon (https://www.centreon.com/)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the spceific language governing permissions and
 * limitations under the License.
 *
 * For more information : contact@centreon.com
 *
 */

declare(strict_types=1);

namespace Core\Security\Authentication\Infrastructure\Provider;

use Centreon\Domain\Authentication\Exception\AuthenticationException as LegacyAuthenticationException;
use Centreon\Domain\Contact\Interfaces\ContactInterface;
use Centreon\Domain\Contact\Interfaces\ContactServiceInterface;
use Centreon\Domain\Log\LoggerTrait;
use Core\Security\Authentication\Application\Provider\ProviderInterface;
use Core\Security\Authentication\Application\UseCase\Login\LoginRequest;
use Core\Security\Authentication\Domain\Model\AuthenticationTokens;
use Core\Security\Authentication\Domain\Model\NewProviderToken;
use Core\Security\Authentication\Domain\Model\ProviderToken;
use Core\Security\ProviderConfiguration\Domain\Model\Configuration;
use Exception;
use Security\Domain\Authentication\Interfaces\LocalProviderInterface;
use Security\Domain\Authentication\Interfaces\ProviderServiceInterface;
use Security\Domain\Authentication\Model\LocalProvider;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Throwable;

final class Local implements ProviderInterface
{
    use LoggerTrait;

    /** @var string */
    private string $username;

    /**
     * @param LocalProviderInterface $provider
     * @param ProviderServiceInterface $providerService
     * @param SessionInterface $session
     */
    public function __construct(private LocalProviderInterface   $provider,
                                private ProviderServiceInterface $providerService,
                                private SessionInterface         $session,
                                private ContactServiceInterface  $contactService)
    {
    }

    /**
     * @param LoginRequest $request
     * @return void
     * @throws Throwable
     */
    public function authenticateOrFail(LoginRequest $request): void
    {
        $this->debug(
            '[AUTHENTICATE] Authentication using provider',
            ['provider_name' => LocalProvider::NAME]
        );

        $this->provider->authenticateOrFail([
            'login' => $request->getUsername(),
            'password' => $request->getPassword()
        ]);

        $this->username = $request->getUsername();
    }

    /**
     * @return ContactInterface
     * @throws Exception
     */
    public function findUserOrFail(): ContactInterface
    {
        $this->info('[AUTHENTICATE] Retrieving user informations from provider');
        $user = $this->provider->getUser();
        if ($user === null) {
            $this->critical('[AUTHENTICATE] No contact could be found from provider',
                ['provider_name' => $this->provider->getConfiguration()->getName()]
            );

            // TODO return a custom exception
            throw new Exception("user not found...");
        }

        return $user;
    }

    /**
     * @return string
     */
    public function getUsername(): string
    {
        return $this->username;
    }

    /**
     * @return bool
     */
    public function isAutoImportSupported(): bool
    {
        return $this->provider->canCreateUser();
    }

    /**
     * @return void
     * @throws LegacyAuthenticationException
     */
    public function autoImport(): void
    {
        $user = $this->provider->getUser();
        if (!$this->contactService->exists($user)) {
            if ($this->provider->canCreateUser()) {
                $this->debug(
                    '[AUTHENTICATE] Provider is allowed to create user. Creating user...',
                    ['user' => $user->getAlias()]
                );
                $this->contactService->addUser($user);
            } else {
                throw LegacyAuthenticationException::userNotFoundAndCannotBeCreated();
            }
        } else {
            $this->contactService->updateUser($user);
        }
    }

    /**
     * @return void
     */
    public function updateACL(): void
    {

    }

    /**
     * @return \Centreon
     */
    public function getLegacySession(): \Centreon
    {
        return $this->provider->getLegacySession();
    }

    /**
     * @return ProviderToken
     */
    public function getProviderToken(): NewProviderToken
    {
        return $this->provider->getProviderToken($this->session->getId());
    }

    /**
     * @return ProviderToken|null
     */
    public function getProviderRefreshToken(): ?ProviderToken
    {
        return $this->provider->getProviderRefreshToken($this->session->getId());
    }

    /**
     * @return Configuration
     */
    public function getConfiguration(): Configuration
    {
        return $this->provider->getConfiguration();
    }

    /**
     * @param Configuration $configuration
     * @return void
     */
    public function setConfiguration(Configuration $configuration): void
    {
        $this->provider->setConfiguration($configuration);
    }

    /**
     * @return bool
     */
    public function isUpdateACLSupported(): bool
    {
        return false;
    }

    /**
     * @return bool
     */
    public function canRefreshToken(): bool
    {
        return false;
    }

    /**
     * @param AuthenticationTokens $authenticationTokens
     * @return AuthenticationTokens|null
     */
    public function refreshToken(AuthenticationTokens $authenticationTokens): ?AuthenticationTokens
    {
        return null;
    }

    /**
     * @return ContactInterface
     */
    public function getAuthenticatedUser(): ContactInterface
    {
        return $this->provider->getUser();
    }

}