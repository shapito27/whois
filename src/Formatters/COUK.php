<?php

namespace Shapito27\Whois\Formatters;

class COUK extends BaseFormatter
{
    public $eol = "\n\n";

    /**
     * @param  string  $whoisPlainText
     *
     * @return string
     */
    protected function reformatWhoisPlainText(string $whoisPlainText): string
    {
        $whoisPlainText = str_replace(
            ["Expiry date:", "Registered on:", "Last updated:"],
            ["\n\nExpiry date:", "\n\nRegistered on:", "\n\nLast updated:"],
            $whoisPlainText
        );

        return $whoisPlainText;
    }
}