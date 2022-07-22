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

namespace CentreonRemote\Infrastructure\Export;

use CentreonRemote\Infrastructure\Export\ExportParserInterface;
use Symfony\Component\Yaml\Yaml;

class ExportParserYaml implements ExportParserInterface
{
    /**
     * @param callable|null $macros
     * @return array<mixed>
     */
    public function parse(string $filename, callable $macros = null): array
    {
        if (!file_exists($filename)) {
            return [];
        }

        $content = file_get_contents($filename);

        if ($macros !== null) {
            $macros($content);
        }

        $value = Yaml::parse($content);

        return $value;
    }

    /**
     * @param string[] $input
     */
    public function dump(array $input, string $filename): void
    {
        if (!$input) {
            return;
        }

        $yaml = Yaml::dump($input);

        file_put_contents($filename, $yaml);
    }
}
