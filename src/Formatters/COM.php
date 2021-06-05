<?php

namespace Shapito27\Whois\Formatters;

class COM extends BaseFormatter
{
    public function __construct()
    {
        parent::__construct();

        $this->setDomainAvailableSynonyms(['No match for domain ']);
    }
}