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

    /**
     * Custom creation date parse. Need to remove part at the end: (GMT+0:00)
     * @param  string  $whoisString
     *
     * @return string|null
     */
    protected function parseCreationDate(string $whoisString): ?string
    {
        foreach ($this->creationDateSynonyms as $creationDateSynonym) {
            if (stripos($whoisString, $creationDateSynonym) !== false) {
                if (($pos = stripos($whoisString, '(GMT')) !== false) {
                    $whoisString = trim(substr($whoisString, 0, $pos,));
                }
                $creationDate = trim(str_ireplace($creationDateSynonym, '', $whoisString));
                $creationDate = $this->afterCreationDateFound($creationDate);
                if (!empty($creationDate)) {
                    return $this->parseDate($creationDate);
                }
            }
        }

        return null;
    }

    /**
     * Custom update date parse. Need to remove part at the end: (GMT+0:00)
     * @param  string  $whoisString
     *
     * @return string|null
     */
    protected function parseUpdateDate(string $whoisString): ?string
    {
        foreach ($this->updateDateSynonyms as $updateDateSynonym) {
            if (stripos($whoisString, $updateDateSynonym) !== false) {
                if (($pos = stripos($whoisString, '(GMT')) !== false) {
                    $whoisString = trim(substr($whoisString, 0, $pos,));
                }
                $updateDate = trim(str_ireplace($updateDateSynonym, '', $whoisString));
                if (!empty($updateDate)) {
                    return $this->parseDate($updateDate);
                }
            }
        }

        return null;
    }
}