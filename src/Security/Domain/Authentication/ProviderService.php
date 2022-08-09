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

namespace Security\Domain\Authentication;

use Centreon\Domain\Log\LoggerTrait;
use Core\Security\ProviderConfiguration\Application\Repository\ReadConfigurationFactory;
use Exception;
use Security\Domain\Authentication\Model\ProviderConfiguration;
use Centreon\Domain\Authentication\Exception\AuthenticationException;
use Security\Domain\Authentication\Exceptions\ProviderException;
use Security\Domain\Authentication\Interfaces\ProviderServiceInterface;
use Security\Domain\Authentication\Interfaces\AuthenticationRepositoryInterface;
use Security\Domain\Authentication\Interfaces\ProviderRepositoryInterface;
use Core\Security\Authentication\Application\Provider\ProviderInterface;
use Security\Domain\Authentication\Model\ProviderFactory;

class ProviderService implements ProviderServiceInterface
{
    use LoggerTrait;

    /**
     * @param AuthenticationRepositoryInterface $authenticationRepository
     * @param ProviderRepositoryInterface $providerRepository
     * @param ProviderFactory $providerFactory
     * @param ReadConfigurationFactory $readConfigurationFactory
     */
    public function __construct(
        private AuthenticationRepositoryInterface $authenticationRepository,
        private ProviderRepositoryInterface $providerRepository,
        private ProviderFactory $providerFactory,
        private ReadConfigurationFactory $readConfigurationFactory
    ) {
    }

    /**
     * @inheritDoc
     */
    public function findProviderByConfigurationId(int $providerConfigurationId): ?ProviderInterface
    {
        try {
            $configuration = $this->readConfigurationFactory->getConfigurationById($providerConfigurationId);
        } catch (\Exception $ex) {
            throw ProviderException::findProvidersConfigurations($ex);
        }

        return $this->providerFactory->create($configuration);
    }

    /**
     * @inheritDoc
     */
    public function findProviderByConfigurationName(string $providerConfigurationName): ?ProviderInterface
    {
        $this->info("[PROVIDER SERVICE] Looking for provider '$providerConfigurationName'");
        try {
            $configuration = $this->readConfigurationFactory->getConfigurationByName($providerConfigurationName);
        } catch (\Exception $ex) {
            throw ProviderException::findProviderConfiguration($providerConfigurationName, $ex);
        }

        return $this->providerFactory->create($configuration);
    }

    /**
     * @inheritDoc
     */
    public function findProviderBySession(string $token): ?ProviderInterface
    {
        try {
            $authenticationToken = $this->authenticationRepository->findAuthenticationTokensByToken($token);
        } catch (\Exception $ex) {
            throw AuthenticationException::findAuthenticationToken($ex);
        }
        if ($authenticationToken === null) {
            return null;
        }
        return $this->findProviderByConfigurationId($authenticationToken->getConfigurationProviderId());
    }

    /**
     * @inheritDoc
     */
    public function findProviderConfigurationByConfigurationName(
        string $providerConfigurationName
    ): ?ProviderConfiguration {
        try {
            return $this->providerRepository->findProviderConfigurationByConfigurationName($providerConfigurationName);
        } catch (Exception $ex) {
            throw ProviderException::findProviderConfiguration($providerConfigurationName, $ex);
        }
    }
}
