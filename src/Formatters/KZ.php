<?php

namespace Shapito27\Whois\Formatters;

use Shapito27\Whois\Registrar;
use Shapito27\Whois\Whois;

class KZ extends BaseFormatter
{
    public function __construct()
    {
        parent::__construct();

        $this->setCreationDateSynonyms(['Domain created:']);
        $this->setUpdateDateSynonyms(['Last modified :', 'Last modified:']);
        $this->setNameServerSynonyms(['Primary server.........:', 'Secondary server.......:']);
        $this->setRegistrarSynonyms(['Current Registar:']);
    }
}