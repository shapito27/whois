<?php

namespace Shapito27\Whois;

/**
 * Class Whois
 * @package Shapito27\Whois
 */
class Whois
{
    /** @var string */
    public $creationDate;
    /** @var string */
    public $updateDate;
    /** @var string */
    public $expirationDate;

    /** @var array */
    public $nameServers = [];

    /** @var Registrar */
    public $registrar;

    /** @var string */
    public $registryDomainId;
}
