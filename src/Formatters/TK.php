<?php

namespace Shapito27\Whois\Formatters;

use Shapito27\Whois\Registrar;
use Shapito27\Whois\Whois;

class TK extends BaseFormatter
{
    public function __construct()
    {
        parent::__construct();

        $this->setCreationDateSynonyms(['Domain registered:']);
        $this->setExpiryDateSynonyms(['Record will expire on:']);
        $this->setNameServerSynonyms(['Domain Nameservers:']);
    }

    /**
     * @param  array  $whoisStrings
     *
     * @return array
     */
    protected function parseNameServers(array $whoisStrings): array
    {
        $nameServersList   = [];
        $keywordNSFound    = false;
        $nameServerSynonym = $this->nameServerSynonyms[0];
        //parse name servers
        foreach ($whoisStrings as $line) {
            $nameServer = null;
            if ($keywordNSFound === true) {
                $nameServer = trim(str_replace(["\t", "\n"], '', $line));
                if (empty($nameServer)) {
                    break;
                }
                if (in_array($nameServer, $nameServersList, true) === false) {
                    $nameServersList[] = $nameServer;
                }
            }
            if ((stripos($line, $nameServerSynonym) !== false)) {
                $keywordNSFound = true;
            }
        }

        return $nameServersList;
    }
}