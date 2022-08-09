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

use Centreon\Domain\Contact\Interfaces\ContactInterface;
use Centreon\Domain\Log\LoggerTrait;
use Centreon\Domain\Repository\Interfaces\DataStorageEngineInterface;
use Core\Contact\Application\Repository\WriteContactGroupRepositoryInterface;
use Core\Security\AccessGroup\Application\Repository\WriteAccessGroupRepositoryInterface;
use Core\Security\AccessGroup\Domain\Model\AccessGroup;
use Core\Security\Authentication\Application\Provider\ProviderInterface;

final class AclUpdater implements AclUpdaterInterface
{
    use LoggerTrait;

    /**
     * @var ProviderInterface
     */
    private ProviderInterface $provider;

    /**
     * @param DataStorageEngineInterface $dataStorageEngine
     * @param WriteContactGroupRepositoryInterface $contactGroupRepository
     * @param WriteAccessGroupRepositoryInterface $accessGroupRepository
     */
    public function __construct(
        private DataStorageEngineInterface $dataStorageEngine,
        private WriteContactGroupRepositoryInterface $contactGroupRepository,
        private WriteAccessGroupRepositoryInterface $accessGroupRepository,
    )
    {
    }

    /**
     * @param ProviderInterface $provider
     * @param ContactInterface $user
     * @return void
     */
    public function updateForProviderAndUser(ProviderInterface $provider, ContactInterface $user): void
    {
        $this->provider= $provider;
        if ($provider->isUpdateACLSupported()) {
            $userClaims = $provider->getUserClaims();
            $userAccessGroups = $provider->getUserAccessGroupsFromClaims($userClaims);
            $this->updateAccessGroupsForUser($user, $userAccessGroups);
            $this->updateContactGroupsForUser($user);
        }
    }

    /**
     * Delete and Insert Access Groups for authenticated user
     *
     * @param ContactInterface $user
     * @param AccessGroup[] $userAccessGroups
     */
    private function updateAccessGroupsForUser(ContactInterface $user, array $userAccessGroups): void
    {
        try {

            $this->info("Updating User Access Groups", [
                "user_id" => $user->getId(),
                "access_groups" => $userAccessGroups
            ]);
            $this->dataStorageEngine->startTransaction();
            $this->accessGroupRepository->deleteAccessGroupsForUser($user);
            $this->accessGroupRepository->insertAccessGroupsForUser($user, $userAccessGroups);
            $this->dataStorageEngine->commitTransaction();
        } catch (\Exception $ex) {
            $this->dataStorageEngine->rollbackTransaction();
            $this->error('Error during ACL update', [
                "user_id" => $user->getId(),
                "access_groups" => $userAccessGroups,
                "trace" => $ex->getTraceAsString()
            ]);
        }
    }
    /**

     * Delete and Insert Contact Group for authenticated user
     *
     * @param ContactInterface $user
     */
    private function updateContactGroupsForUser(ContactInterface $user): void
    {
        $contactGroup = $this->provider->getConfiguration()->getCustomConfiguration()->getContactGroup();

        try {
            $this->info('Updating User Contact Group', [
                "user_id" => $user->getId(),
                "contact_group_id" => $contactGroup->getId(),
            ]);
            $this->dataStorageEngine->startTransaction();
            $this->contactGroupRepository->deleteContactGroupsForUser($user);
            $this->contactGroupRepository->insertContactGroupForUser($user, $contactGroup);
            $this->dataStorageEngine->commitTransaction();
        } catch (\Exception $ex) {
            $this->dataStorageEngine->rollbackTransaction();
            $this->error('Error during contact group update', [
                "user_id" => $user->getId(),
                "contact_group_id" => $contactGroup->getId(),
                "trace" => $ex->getTraceAsString()
            ]);
        }
    }
}