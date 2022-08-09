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
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * For more information : contact@centreon.com
 *
 */

declare(strict_types=1);

namespace Core\Security\ProviderConfiguration\Infrastructure\Repository;

use Centreon\Domain\Repository\RepositoryException;
use Centreon\Infrastructure\DatabaseConnection;
use Centreon\Infrastructure\Repository\AbstractRepositoryDRB;
use Core\Security\Authentication\Domain\Provider\OpenIdProvider;
use Core\Security\ProviderConfiguration\Application\Local\Repository\ReadConfigurationRepositoryInterface;
use Core\Security\ProviderConfiguration\Application\OpenId\Repository\ReadOpenIdConfigurationRepositoryInterface;
use Core\Security\ProviderConfiguration\Application\Repository\ReadConfigurationFactory;
use Core\Security\ProviderConfiguration\Domain\CustomConfigurationInterface;
use Core\Security\ProviderConfiguration\Domain\Local\Model\CustomConfiguration as LocalCustomConfiguration;
use Core\Security\ProviderConfiguration\Domain\Model\Configuration;
use Core\Security\ProviderConfiguration\Domain\OpenId\Exceptions\OpenIdConfigurationException;
use Core\Security\ProviderConfiguration\Domain\OpenId\Model\CustomConfiguration as OpenIdCustomConfiguration;
use PDO;
use Security\Domain\Authentication\Model\LocalProvider;
use Throwable;
use function json_decode;

final class DbReadConfigurationFactoryRepository extends AbstractRepositoryDRB implements ReadConfigurationFactory
{
    public function __construct(
        DatabaseConnection                           $db,
        private ReadConfigurationRepositoryInterface $localConfigurationRepository,
        private ReadOpenIdConfigurationRepositoryInterface $readOpenIdConfigurationRepository
    )
    {
        $this->db = $db;
    }

    /**
     * @param string $providerName
     * @return Configuration
     * @throws Throwable
     */
    public function getConfigurationByName(string $providerName): Configuration
    {
        $configuration = $this->loadConfigurationByName($providerName);
        $customConfiguration = $this->loadCustomConfigurationFromConfiguration($configuration);
        $configuration->setCustomConfiguration($customConfiguration);

        return $configuration;
    }

    /**
     * @param int $id
     * @return Configuration
     * @throws OpenIdConfigurationException
     * @throws RepositoryException
     */
    public function getConfigurationById(int $id): Configuration
    {
        $configuration = $this->loadConfigurationById($id);
        $customConfiguration = $this->loadCustomConfigurationFromConfiguration($configuration);
        $configuration->setCustomConfiguration($customConfiguration);

        return $configuration;
    }

    /**
     * @param Configuration $configuration
     * @return CustomConfigurationInterface
     * @throws OpenIdConfigurationException
     * @throws RepositoryException
     */
    private function loadCustomConfigurationFromConfiguration(Configuration $configuration): CustomConfigurationInterface
    {
        switch ($configuration->getName()) {
            case LocalProvider::NAME:
//                $jsonSchemaValidatorFile = __DIR__ . '/../Local/Repository/CustomConfigurationSchema.json';
//                $this->validateJsonRecord($configuration->getJsonCustomConfiguration(), $jsonSchemaValidatorFile);
                $excludedUserAliases = array_map(
                    fn($user) => $user['contact_alias'],
                    $this->localConfigurationRepository->findExcludedUsers()
                );
                return LocalCustomConfiguration::createFromJsonArray(
                    json_decode($configuration->getJsonCustomConfiguration(), true),
                    $excludedUserAliases
                );
            case OpenIdProvider::NAME:
                $jsonSchemaValidatorFile = __DIR__ . '/../OpenId/Repository/CustomConfigurationSchema.json';
                $json = $configuration->getJsonCustomConfiguration();
                $this->validateJsonRecord($json, $jsonSchemaValidatorFile);
                $jsonArray = json_decode($json, true);
                $jsonArray['contact_template'] = $jsonArray['contact_template_id'] !== null
                    ? $this->readOpenIdConfigurationRepository->getContactTemplate($jsonArray['contact_template_id'])
                    : null;
                $jsonArray['contact_group'] = $jsonArray['contact_group_id'] !== null
                    ? $this->readOpenIdConfigurationRepository->getContactGroup($jsonArray['contact_group_id'])
                    : null;
                $jsonArray["authorization_rules"] =
                    $this->readOpenIdConfigurationRepository->getAuthorizationRulesByConfigurationId($configuration->getId());

                return new OpenIdCustomConfiguration($jsonArray);
            default:
                throw new \Exception("unknown configuration name, can't load custom config");

        }
    }
    /**
     * @param string $providerName
     * @return Configuration
     */
    private function loadConfigurationByName(string $providerName): Configuration
    {
        $query = $this->translateDbName(
            sprintf("SELECT *
                FROM `:db`.`provider_configuration`
                WHERE `name` = '%s'", $providerName)
        );

        $statement = $this->db->query($query);
        $result = $statement->fetch(PDO::FETCH_ASSOC);

        return new Configuration(
            (int)$result['id'],
            $result['name'],
            $result['type'],
            $result['custom_configuration'],
            (bool)$result['is_active'],
            (bool)$result['is_forced']);
    }

    /**
     * @param int $id
     * @return Configuration
     */
    private function loadConfigurationById(int $id): Configuration
    {
        $query = $this->translateDbName(
            sprintf("SELECT *
                FROM `:db`.`provider_configuration`
                WHERE `id` = '%d'", $id)
        );

        $statement = $this->db->query($query);
        $result = $statement->fetch(PDO::FETCH_ASSOC);

        return new Configuration(
            (int)$result['id'],
            $result['name'],
            $result['type'],
            $result['custom_configuration'],
            (bool)$result['is_active'],
            (bool)$result['is_forced']);
    }


    /**
     * @return array|Configuration[]
     * @throws Throwable
     */
    public function getConfigurations(): array
    {
        $configurations = [];
        $query = $this->translateDbName("SELECT name FROM `:db`.`provider_configuration` where name <> 'web-sso'");
        $statement = $this->db->query($query);
        while ($result = $statement->fetch(PDO::FETCH_ASSOC)) {
           $configurations[] = $this->getConfigurationByName($result['name']);
        }

        return $configurations;
    }
}
