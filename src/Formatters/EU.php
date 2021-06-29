<?php

namespace Shapito27\Whois\Formatters;

/**
 * Class EU
 * @package Shapito27\Whois\Formatters
 */
class EU extends BaseFormatter
{
    public function __construct()
    {
        parent::__construct();

        $this->setDomainAvailableSynonyms(['Status: AVAILABLE']);
        $this->setRegistrarSynonyms(['Organisation:']);
    }
}