<?php

namespace Shapito27\Whois\Formatters;

class FR extends BaseFormatter
{
    public function __construct()
    {
        parent::__construct();

        $this->setUpdateDateSynonyms(['last-update:']);
    }
}