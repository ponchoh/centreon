<?php

/*
 * Copyright 2005 - 2021 Centreon (https://www.centreon.com/)
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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * For more information : contact@centreon.com
 *
 */
declare(strict_types=1);

namespace Centreon\Domain\Authentication\UseCase;

use Centreon\Domain\Authentication\Exception\AuthenticationException;
use Centreon\Domain\Contact\Interfaces\ContactInterface;
use Centreon\Domain\Log\LoggerTrait;
use Core\Security\Authentication\Application\Provider\ProviderInterface;
use Core\Security\Authentication\Application\Repository\WriteTokenRepositoryInterface;
use Core\Security\Authentication\Application\UseCase\Login\LoginRequest;
use Core\Security\Authentication\Domain\Model\NewProviderToken;
use Core\Security\Authentication\Infrastructure\Provider\ProviderFactory;
use Core\Security\ProviderConfiguration\Domain\Model\Configuration;
use Exception;
use InvalidArgumentException;
use Security\Domain\Authentication\Exceptions\ProviderException;
use Security\Domain\Authentication\Interfaces\AuthenticationServiceInterface;
use Security\Domain\Authentication\Interfaces\ProviderServiceInterface;
use Security\Domain\Authentication\Model\LocalProvider;
use Security\Encryption;

class AuthenticateApi
{
    use LoggerTrait;

    /**
     * @param AuthenticationServiceInterface $authenticationService
     * @param ProviderServiceInterface $providerService
     * @param WriteTokenRepositoryInterface $writeTokenRepository
     * @param ProviderFactory $providerFactory
     */
    public function __construct(
        private AuthenticationServiceInterface $authenticationService,
        private ProviderServiceInterface $providerService,
        private WriteTokenRepositoryInterface $writeTokenRepository,
        private ProviderFactory $providerFactory
    ) {
    }

    /**
     * @param AuthenticateApiRequest $request
     * @throws ProviderException
     * @throws AuthenticationException
     */
    public function execute(AuthenticateApiRequest $request, AuthenticateApiResponse $response): void
    {
        $this->info(sprintf("[AUTHENTICATE API] Beginning API authentication for contact '%s'", $request->getLogin()));
        $this->deleteExpiredToken();

        $localProvider = $this->findLocalProviderOrFail();
        $this->authenticateOrFail($localProvider, $request);

        $contact = $this->getUserFromProviderOrFail($localProvider);
        $token = Encryption::generateRandomString();
        $this->createAPIAuthenticationTokens(
            $token,
            $localProvider->getConfiguration(),
            $contact,
            $localProvider->getProviderToken($token),
            null
        );
        $response->setApiAuthentication($contact, $token);
        $this->debug(
            "[AUTHENTICATE API] Authentication success",
            [
                "provider_name" => LocalProvider::NAME,
                "contact_id" => $contact->getId(),
                "contact_alias" => $contact->getAlias()
            ]
        );
    }

    /**
     * Delete all expired Security tokens.
     */
    private function deleteExpiredToken(): void
    {
        /**
         * Remove all expired token before starting authentication process.
         */
        try {
            $this->authenticationService->deleteExpiredSecurityTokens();
        } catch (AuthenticationException $ex) {
            $this->notice('[AUTHENTICATE API] Unable to delete expired security tokens');
        }
    }

    /**
     * Find the local provider or throw an Exception.
     *
     * @return ProviderInterface
     * @throws ProviderException
     */
    private function findLocalProviderOrFail(): ProviderInterface
    {
        return $this->providerFactory->create(Configuration::LOCAL);
    }

    /**
     * Authenticate the user or throw an Exception.
     *
     * @param ProviderInterface $localProvider
     * @param AuthenticateApiRequest $request
     * @throws AuthenticationException
     */
    private function authenticateOrFail(ProviderInterface $localProvider, AuthenticateApiRequest $request): void
    {
        /**
         * Authenticate with the legacy mechanism encapsulated into the Local Provider.
         */
        $this->debug('[AUTHENTICATE API] Authentication using provider', ['provider_name' => Configuration::LOCAL]);
        $request = LoginRequest::createForLocal(Configuration::LOCAL, $request->getLogin(), $request->getPassword());
        $localProvider->authenticateOrFail($request);
    }

    /**
     * Retrieve user from provider or throw an Exception.
     *
     * @param ProviderInterface $localProvider
     * @return ContactInterface
     * @throws AuthenticationException
     */
    private function getUserFromProviderOrFail(ProviderInterface $localProvider): ContactInterface
    {
        $this->info('[AUTHENTICATE API] Retrieving user informations from provider');

        $contact = $localProvider->getAuthenticatedUser();

        /**
         * Contact shouldn't be null in this case as the LocalProvider::authenticate method check if the user exists.
         * But the ProviderInterface::getUser method could return a ContactInterface or null
         * so we need to do this check.
         */
        if ($contact === null) {
            $this->critical(
                '[AUTHENTICATE API] No contact could be found from provider',
                ['provider_name' => LocalProvider::NAME]
            );
            throw AuthenticationException::userNotFound();
        }

        return $contact;
    }

    /**
     * @param string $token
     * @param Configuration $providerConfiguration
     * @param ContactInterface $contact
     * @param NewProviderToken $providerToken
     * @param NewProviderToken|null $providerRefreshToken
     * @return void
     * @throws AuthenticationException
     */
    public function createAPIAuthenticationTokens(
        string $token,
        Configuration $providerConfiguration,
        ContactInterface $contact,
        NewProviderToken $providerToken,
        ?NewProviderToken $providerRefreshToken
    ): void {
        $this->debug(
            '[AUTHENTICATE API] Creating authentication tokens for user',
            ['user' => $contact->getAlias()]
        );
        if ($providerConfiguration->getId() === null) {
            throw new InvalidArgumentException("Provider configuration can't be null");
        }
        try {
            $this->writeTokenRepository->createAuthenticationTokens(
                $token,
                $providerConfiguration->getId(),
                $contact->getId(),
                $providerToken,
                $providerRefreshToken
            );
        } catch (Exception $ex) {
            throw AuthenticationException::addAuthenticationToken($ex);
        }
    }
}
