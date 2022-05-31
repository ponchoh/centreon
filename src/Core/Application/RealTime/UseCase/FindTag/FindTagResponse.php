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

namespace Core\Application\RealTime\UseCase\FindTag;

use Core\Domain\RealTime\Model\Tag;

class FindTagResponse
{
    /**
     * @var array<int, array<string, int|string>>
     */
    public array $tags;

    /**
     * @param Tag[] $tags
     */
    public function __construct(array $tags)
    {
        $this->tags = $this->tagsToArray($tags);
    }

    /**
     * Convert array of HostCategory models into an array made of scalars
     *
     * @param Tag[] $tags
     * @return array<int, array<string, int|string>>
     */
    private function tagsToArray(array $tags): array
    {
        return array_map(
            fn (Tag $tag) => [
                'id' => $tag->getId(),
                'name' => $tag->getName()
            ],
            $tags
        );
    }
}
