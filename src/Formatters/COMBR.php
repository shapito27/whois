<?php

namespace Shapito27\Whois\Formatters;

class COMBR extends BaseFormatter
{
    protected function afterCreationDateFound(string $creationDate): string
    {
        if (($hashSign = strpos($creationDate, '#')) !== false) {
            return trim(substr($creationDate, 0, $hashSign));
        }

        return $creationDate;
    }
}