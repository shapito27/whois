<?php

namespace Shapito27\Whois\Formatters;

use Shapito27\Whois\Registrar;
use Shapito27\Whois\Whois;

class SI extends BaseFormatter
{
    /**
     * @param  string  $whoisPlainText
     *
     * @return string
     */
    protected function reformatWhoisPlainText(string $whoisPlainText): string
    {
        if (($domainKeysordPos = strpos($whoisPlainText, 'domain:')) !== false) {
            return substr($whoisPlainText, $domainKeysordPos);
        }

        return $whoisPlainText;
    }
}