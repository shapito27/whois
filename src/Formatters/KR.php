<?php

namespace Shapito27\Whois\Formatters;

class KR extends BaseFormatter
{
    /**
     * @param  string  $whoisString
     *
     * @return string|null
     */
    protected function parseCreationDate(string $whoisString): ?string
    {
        foreach ($this->creationDateSynonyms as $creationDateSynonym) {
            if (stripos($whoisString, $creationDateSynonym) !== false) {
                if (strpos($whoisString, $this->unnecessaryWord) !== false) {
                    $whoisString = str_replace($this->unnecessaryWord, '', $whoisString);
                }
                $creationDate = trim(str_ireplace([$creationDateSynonym, '. ', '.'], ['', '', ''], $whoisString));
                $creationDate = $this->afterCreationDateFound($creationDate);
                if (!empty($creationDate)) {
                    return $this->parseDate($creationDate);
                }
            }
        }

        return null;
    }

    /**
     * @param  string  $whoisString
     *
     * @return string|null
     */
    protected function parseExpirationDate(string $whoisString): ?string
    {
        foreach ($this->expiryDateSynonyms as $expiryDateSynonym) {
            if (stripos($whoisString, $expiryDateSynonym) !== false) {
                $expirationDate = trim(str_ireplace([$expiryDateSynonym, '. ', '.'], ['', '', ''], $whoisString));
                if (!empty($expirationDate)) {
                    return $this->parseDate($expirationDate);
                }
            }
        }

        return null;
    }

    /**
     * @param  string  $whoisString
     *
     * @return string|null
     */
    protected function parseUpdateDate(string $whoisString): ?string
    {
        foreach ($this->updateDateSynonyms as $updateDateSynonym) {
            if (stripos($whoisString, $updateDateSynonym) !== false) {
                $updateDate = trim(str_ireplace([$updateDateSynonym, '. ', '.'], ['', '', ''], $whoisString));
                if (!empty($updateDate)) {
                    return $this->parseDate($updateDate);
                }
            }
        }

        return null;
    }
}