<?php
/*
 * Copyright 2005-2019 Centreon
 * Centreon is developped by : Julien Mathis and Romain Le Merlus under
 * GPL Licence 2.0.
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation ; either version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, see <http://www.gnu.org/licenses>.
 *
 * Linking this program statically or dynamically with other modules is making a
 * combined work based on this program. Thus, the terms and conditions of the GNU
 * General Public License cover the whole combination.
 *
 * As a special exception, the copyright holders of this program give Centreon
 * permission to link this program with independent modules to produce an executable,
 * regardless of the license terms of these independent modules, and to copy and
 * distribute the resulting executable under terms of Centreon choice, provided that
 * Centreon also meet, for each linked independent module, the terms  and conditions
 * of the license of that module. An independent module is a module which is not
 * derived from this program. If you modify this program, you may extend this
 * exception to your version of the program, but you are not obliged to do so. If you
 * do not wish to do so, delete this exception statement from your version.
 *
 * For more information : contact@centreon.com
 *
 *
 */

namespace CentreonModule\Infrastructure\Entity;

use CentreonModule\Infrastructure\Source\SourceDataInterface;

class Module implements SourceDataInterface
{
    private ?string $id = null;

    private ?string $type = null;

    private ?string $name = null;

    private ?string $description = null;

    /**
     * @var array<int,string>
     */
    private array $images = [];

    private ?string $author = null;

    private ?string $version = null;

    private ?string $versionCurrent = null;

    private ?string $path = null;

    private string $stability = 'stable';

    private ?string $keywords = null;

    /**
     * @var array<string,string|bool>
     */
    private $license;

    /**
     * @var string
     */
    protected $lastUpdate;

    /**
     * @var string
     */
    protected $releaseNote;

    private bool $isInstalled = false;

    private bool $isUpdated = false;

    public function getId(): string
    {
        return $this->id;
    }

    public function setId(string $id): void
    {
        $this->id = $id;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function setType(string $type): void
    {
        $this->type = $type;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function setName(string $name): void
    {
        $this->name = $name;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    public function setDescription(string $description): void
    {
        $this->description = $description;
    }

    /**
     * @return array<int,string>
     */
    public function getImages(): array
    {
        return $this->images;
    }

    public function addImage(string $image): void
    {
        $this->images[] = $image;
    }

    public function getAuthor(): string
    {
        return $this->author;
    }

    public function setAuthor(string $author): void
    {
        $this->author = $author;
    }

    public function getVersion(): string
    {
        return $this->version;
    }

    public function setVersion(string $version): void
    {
        $this->version = $version;
    }

    /**
     * @return string
     */
    public function getVersionCurrent(): ?string
    {
        return $this->versionCurrent;
    }

    public function setVersionCurrent(string $versionCurrent): void
    {
        $this->versionCurrent = $versionCurrent;
    }

    public function getPath(): string
    {
        return $this->path;
    }

    public function setPath(string $path): void
    {
        $this->path = $path;
    }

    public function getStability(): string
    {
        return $this->stability;
    }

    public function setStability(string $stability): void
    {
        $this->stability = $stability;
    }

    public function getKeywords(): string
    {
        return $this->keywords;
    }

    public function setKeywords(string $keywords): void
    {
        $this->keywords = $keywords;
    }

    /**
     * @return array<string,string|bool>|null
     */
    public function getLicense(): ?array
    {
        return $this->license;
    }

    /**
     * @param array<mixed>|null $license
     */
    public function setLicense(array $license = null): void
    {
        $this->license = $license;
    }

    public function getLastUpdate(): ?string
    {
        return $this->lastUpdate;
    }

    public function setLastUpdate(string $lastUpdate): void
    {
        $this->lastUpdate = $lastUpdate;
    }

    public function getReleaseNote(): ?string
    {
        return $this->releaseNote;
    }

    public function setReleaseNote(string $releaseNote): void
    {
        $this->releaseNote = $releaseNote;
    }

    public function isInstalled(): bool
    {
        return $this->isInstalled;
    }

    /**
     * @return bool
     */
    public function setInstalled(bool $value): void
    {
        $this->isInstalled = $value;
    }

    public function isUpdated(): bool
    {
        return $this->isUpdated;
    }

    /**
     * @return bool
     */
    public function setUpdated(bool $value): void
    {
        $this->isUpdated = $value;
    }
}
