<?php

namespace Shapito27\Whois\Formatters;

use Carbon\Carbon;
use RuntimeException;
use Shapito27\Whois\Registrar;
use Shapito27\Whois\Whois;

class BaseFormatter extends AbstractFormatter
{
    public $eol = "\n";

    /**
     * @param  string  $whoisPlainText
     *
     * @return Whois
     */
    public function convertToWhoisObject(string $whoisPlainText): Whois
    {
        $parseUpdateInfo            = true;
        $whoisObject = new Whois();

        //reformant Whois Plain Text before explode it to strings
        $whoisPlainText = $this->reformatWhoisPlainText($whoisPlainText);
        $whoisStrings = explode($this->eol, $whoisPlainText);
        //remove empty lines
        foreach ($whoisStrings as $key => $line) {
            if ($line === '') {
                unset($whoisStrings[$key]);
            }
        }
        //reformat each line
        foreach ($whoisStrings as $key => $line) {
            $whoisStrings[$key] = $this->reformatWhoisPlainRow($line);
        }

        foreach ($whoisStrings as $lineNumber => $line) {
            if ($whoisObject->creationDate === null) {
                //looking for creation date
                $whoisObject->creationDate = $this->parseCreationDate($line);
            }

            //looking for expiry date
            if ($whoisObject->expirationDate === null) {
                $whoisObject->expirationDate = $this->parseExpirationDate($line);
            }

            //looking for updated date
            if ($parseUpdateInfo && $whoisObject->updateDate === null) {
                $whoisObject->updateDate = $this->parseUpdateDate($line);
            }

            $whoisObject->registryDomainId = $this->parseRegistryDomainId($line);

            $registrarName = $this->parseRegistrarName($line);;
            if ($whoisObject->registrar === null && $registrarName !== null) {
                $whoisObject->registrar       = new Registrar();
                $whoisObject->registrar->name = $registrarName;
            }

            $registrarId = $this->parseRegistrarId($line);;
            if ($whoisObject->registrar === null && $registrarId !== null) {
                $whoisObject->registrar     = new Registrar();
                $whoisObject->registrar->id = $registrarId;
            }

            foreach ($this->registrarAbuseContactEmailSynonyms as $registrarAbuseContactEmailSynonym) {
                if (stripos($line, $registrarAbuseContactEmailSynonym) !== false) {
                    $registrarAbuseContactEmail = trim(str_ireplace($registrarAbuseContactEmailSynonym, '', $line));
                    if (!empty($registrarAbuseContactEmail)) {
                        if ($whoisObject->registrar === null) {
                            $whoisObject->registrar = new Registrar();
                        }
                        $whoisObject->registrar->abuseContactEmail = $registrarAbuseContactEmail;
                        break;
                    }
                }
            }

            foreach ($this->registrarAbuseContactPhoneSynonyms as $registrarAbuseContactPhoneSynonym) {
                if (stripos($line, $registrarAbuseContactPhoneSynonym) !== false) {
                    $registrarAbuseContactPhone = trim(str_ireplace($registrarAbuseContactPhoneSynonym, '', $line));
                    if (!empty($registrarAbuseContactPhone)) {
                        if ($whoisObject->registrar === null) {
                            $whoisObject->registrar = new Registrar();
                        }
                        $whoisObject->registrar->abuseContactPhone = $registrarAbuseContactPhone;
                        break;
                    }
                }
            }

            //looking for name_servers
            foreach ($this->nameServerSynonyms as $nameServerSynonym) {
                if (stripos($line, $nameServerSynonym) !== false) {
                    $nameServer = strtolower(trim(str_ireplace($nameServerSynonym, '', $line)));
                    if (!empty($nameServer)) {
                        //if have other data we do not need after space
                        if (strpos($nameServer, ' ') !== false) {
                            $nameServer = substr($nameServer, 0, strpos($nameServer, ' '));
                        }
                        if (in_array($nameServer, $whoisObject->nameServers, true) === false) {
                            $whoisObject->nameServers[] = $nameServer;
                        }
                        break;
                    }
                }
            }
        }

        return $whoisObject;
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
        $errors = null;

        //reformant Whois Plain Text before explode it to strings
        $whoisPlainText = $this->reformatWhoisPlainText($whoisPlainText);
        $whoisStrings = explode($this->eol, $whoisPlainText);

        foreach ($whoisStrings as $lineNumber => $line) {
            //if have keyword domain not found it means domain is free
            foreach ($this->domainAvailableSynonyms as $domainNotFoundSynonym) {
                if (strpos($line, $domainNotFoundSynonym) !== false) {
                    $domainAvailable = true;
                    $foundDomainNotFoundSynonym = $domainNotFoundSynonym;
                    break;
                }
            }
        }
        try {
//            if ($parserResult->isDomainAvailable()) {
            if ($domainAvailable === true) {
                if ($whoisObject->expirationDate !== null) {
                    $expirationDate = $this->parseDate($whoisObject->expirationDate);
                    $today          = Carbon::now();
                    if ($today->lessThan($expirationDate)) {
                        throw new RuntimeException(
                            'Found phrase "'.$foundDomainNotFoundSynonym.'" that domain free but domain expiration date is in the future.'
                        );
                    }
                }

                if (!empty($whoisObject->nameServers)) {
                    throw new RuntimeException(
                        'Found phrase "'.$foundDomainNotFoundSynonym.'" that domain free but domain nameServers is not empty.'
                    );
                }

                if (!empty($whoisObject->registrar)) {
                    throw new RuntimeException(
                        'Found phrase "'.$foundDomainNotFoundSynonym.'" that domain free but domain has registrar.'
                    );
                }

                if (!empty($whoisObject->registryDomainId)) {
                    throw new RuntimeException(
                        'Found phrase "'.$foundDomainNotFoundSynonym.'" that domain free but domain has registryDomainId.'
                    );
                }
            }
        } catch (RuntimeException $exception) {
            $domainAvailable = false;
            $errors[] = $exception->getMessage() . ' Availability was switched to false.';
        }

        if (empty($whoisObject->expirationDate) && empty($whoisObject->updateDate)) {
            if ($domainAvailable === false) {
                $errors[] = 'Updated date and Expiration date is not parsed. No phrase that domain is free';
            } else {
                $errors[] = 'Updated date and Expiration date is not parsed. Phrase that domain is free found: "'.$foundDomainNotFoundSynonym.'"';
            }
        }

        return [
            'is_available' => $domainAvailable,
            'errors' => $errors,
        ];
    }

    /**
     * @param  string  $whoisPlainText
     *
     * @return string
     */
    protected function reformatWhoisPlainText(string $whoisPlainText): string
    {
        return $whoisPlainText;
    }

    /**
     * @param  string  $row
     *
     * @return string
     */
    protected function reformatWhoisPlainRow(string $row): string
    {
        return $row;
    }

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
     * @param  string  $whoisString
     *
     * @return string|null
     */
    protected function parseExpirationDate(string $whoisString): ?string
    {
            foreach ($this->expiryDateSynonyms as $expiryDateSynonym) {
                if (stripos($whoisString, $expiryDateSynonym) !== false) {
                    $expirationDate = trim(str_ireplace($expiryDateSynonym, '', $whoisString));
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
                $updateDate = trim(str_ireplace($updateDateSynonym, '', $whoisString));
                if (!empty($updateDate)) {
                    return $this->parseDate($updateDate);
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
    protected function parseRegistryDomainId(string $whoisString): ?string
    {
        foreach ($this->registryDomainIdSynonyms as $registryDomainIdSynonym) {
            if (stripos($whoisString, $registryDomainIdSynonym) !== false) {
                $registryDomainId = trim(str_ireplace($registryDomainIdSynonym, '', $whoisString));
                if (!empty($registryDomainId)) {
                    return $registryDomainId;
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
    protected function parseRegistrarName(string $whoisString): ?string
    {
        foreach ($this->registrarSynonyms as $registrarSynonym) {
            if ((stripos($whoisString, $registrarSynonym) !== false)) {
                $registrarName = trim(str_ireplace($registrarSynonym, '', $whoisString));
                if (!empty($registrarName)) {
                    return $registrarName;
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
    protected function parseRegistrarId(string $whoisString): ?string
    {
        foreach ($this->registrarIanaId as $registrarIanaId) {
            if (stripos($whoisString, $registrarIanaId) !== false) {
                $registrarId = trim(str_ireplace($registrarIanaId, '', $whoisString));
                if (!empty($registrarId)) {
                    return $registrarId;
                }
            }
        }

        return null;
    }

    /**
     * @param  string  $creationDate
     *
     * @return string
     */
    protected function afterCreationDateFound(string $creationDate): string
    {
        return $creationDate;
    }
}
