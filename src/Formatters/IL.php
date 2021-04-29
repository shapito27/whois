<?php

namespace Shapito27\Whois\Formatters;

class IL extends BaseFormatter
{
    protected $pattern = '~\s([0-9]{8,8})\s+\(~';
    protected $creationDateSynonym = 'changed:';

    protected function parseCreationDate(string $whoisString): ?string
    {
        if (stripos($whoisString, $this->creationDateSynonym) !== false) {
            if (strpos($whoisString, $this->unnecessaryWord) !== false) {
                $whoisString = str_replace($this->unnecessaryWord, '', $whoisString);
            }
            $creationDate = trim(str_ireplace($this->creationDateSynonym, '', $whoisString));
            $creationDate = $this->afterCreationDateFound($creationDate);
            if (!empty($creationDate)) {
                return $this->parseDate($creationDate);
            }
        }

        return null;
    }

    protected function afterCreationDateFound(string $creationDate): string
    {
        $matches = null;
        if (preg_match($this->pattern, $creationDate, $matches) === 1 && isset($matches[1])) {
            return $matches[1];
        }

        return $creationDate;
    }

    /**
     * @param  string  $whoisString
     *
     * @return string|null
     */
    protected function parseUpdateDate(string $whoisString): ?string
    {
        return null;
    }
}