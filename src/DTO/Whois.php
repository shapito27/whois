<?php

namespace Shapito27\Whois\DTO;

/**
 * Class Whois
 * @package Shapito27\Whois\DTO
 */
class Whois
{
    /** @var int */
    public $status;

    public $creationDate;
    public $updateDate;
    public $expirationDate;

    /** @var array */
    public $nameServers = [];

    /** @var Registrar */
    public $registrar;

    /** @var string */
    public $registryDomainId;

    /** @var string */
    public $errorMessage;

    /**
     * @return bool
     */
    public function isRegistered(): bool
    {
        return $this->creationDate !== null || $this->expirationDate !== null;
    }
}