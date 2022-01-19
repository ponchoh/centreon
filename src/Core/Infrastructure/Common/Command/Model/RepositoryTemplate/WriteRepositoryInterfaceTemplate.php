<?php

namespace Core\Infrastructure\Common\Command\Model\RepositoryTemplate;

use Core\Infrastructure\Common\Command\Model\FileTemplate;

class WriteRepositoryInterfaceTemplate extends FileTemplate
{
    public function __construct(
        public string $filePath,
        public string $namespace,
        public string $name,
        public bool $exists = false
    ) {
    }
}
