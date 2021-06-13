<?php

namespace Shapito27\Whois\Formatters;

use Shapito27\Whois\Whois;

class BLOGSPOTCOM extends BaseFormatter
{
    public function __construct()
    {
        parent::__construct();

        $this->setDomainAvailableSynonyms(['404 page not found']);
    }

    /**
     * @param  string  $whoisPlainText
     * @param  Whois  $whoisObject
     *
     * @return array
     */
    public function isDomainAvailable(string $whoisPlainText, Whois $whoisObject): array
    {
        $domainAvailable = false;
        /** @var array $errors list of errors */
        $errors = null;
        /** @var int $domainAvailableStatus id identificator of reason why I set available true or false */
        $domainAvailableStatus = self::DOMAIN_NOT_AVAILABLE_STATUS_BY_NO_DATA_PARSED;

        //reformat Whois Plain Text before explode it to strings
        $whoisPlainText = $this->reformatWhoisPlainText($whoisPlainText);
        $whoisStrings   = explode($this->eol, $whoisPlainText);

        foreach ($whoisStrings as $lineNumber => $line) {
            //if have keyword domain not found it means domain is free
            foreach ($this->domainAvailableSynonyms as $domainNotFoundSynonym) {
                if (strpos($line, $domainNotFoundSynonym) !== false) {
                    $domainAvailable            = true;
                    $errors = 'Found keyword that domain is available ' . $domainNotFoundSynonym;
                    $domainAvailableStatus      = self::DOMAIN_AVAILABLE_STATUS_BY_KEYWORD;
                    break;
                }
            }
        }

        return [
            'is_available' => $domainAvailable,
            'errors'       => $errors,
            'status'       => $domainAvailableStatus,
        ];
    }
}