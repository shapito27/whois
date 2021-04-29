<?php

namespace Shapito27\Whois\Formatters;

class UK extends BaseFormatter
{
    public $eol = "\n\n";

    /**
     * @param  string  $whoisPlainText
     *
     * @return string
     */
    protected function reformatWhoisPlainText(string $whoisPlainText): string
    {
        return str_replace("\n\t", ' ', $whoisPlainText);
    }
}