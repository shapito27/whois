<?php

namespace Shapito27\Whois;

/**
 * Class Whois
 * @package Shapito27\Whois
 */
class Whois
{
    /** @var string|null */
    public $creationDate;
    /** @var string|null */
    public $updateDate;
    /** @var string|null */
    public $expirationDate;

    /** @var array */
    public $nameServers = [];

    /** @var Registrar|null */
    public $registrar;

    /** @var string|null */
    public $registryDomainId;
}
