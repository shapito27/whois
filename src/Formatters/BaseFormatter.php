<?php

namespace Shapito27\Whois\Formatters;

use Carbon\Carbon;
use RuntimeException;
use Shapito27\Whois\Registrar;
use Shapito27\Whois\Whois;

class BaseFormatter extends AbstractFormatter
{
    public $eol = "\n";

    public const DOMAIN_AVAILABLE_STATUS_BY_KEYWORD = 1;
    /** @var int domain is available because was found keyword, also creation and expiry date are empty */
    public const DOMAIN_AVAILABLE_STATUS_BY_KEYWORD_CREATION_DATE_EXPIRY_DATE = 2;
    public const DOMAIN_NOT_AVAILABLE_STATUS_BY_CREATED_DATE = 10;
    public const DOMAIN_NOT_AVAILABLE_STATUS_BY_EXPIRY_DATE = 11;
    public const DOMAIN_NOT_AVAILABLE_STATUS_BY_NS = 12;
    public const DOMAIN_NOT_AVAILABLE_STATUS_BY_REGISTRAR = 13;
    public const DOMAIN_NOT_AVAILABLE_STATUS_BY_DOMAIN_ID = 14;
    public const DOMAIN_NOT_AVAILABLE_STATUS_BY_NO_DATA_PARSED = 15;
    public const DOMAIN_NOT_AVAILABLE_STATUS_BY_KEYWORD = 16;
    /** @var int domain is not available because wasn't found keyword, and all this data are found: created date, expiry date, ns */
    public const DOMAIN_NOT_AVAILABLE_STATUS_BY_CREATED_DATE_EXPIRY_DATE_NS_NO_KEYWORD = 17;
    /**
     * @var int domain is not available because all this data are found: created date, expiry date, ns.
     * But at the same time we found keyword. Need to fix keyword if we got this status!
     */
    public const DOMAIN_NOT_AVAILABLE_STATUS_BY_CREATED_DATE_EXPIRY_DATE_NS_WITH_KEYWORD = 18;
    /** @var int domain is not available because wasn't found keyword, and some of this data are found: created date, expiry date, ns */
    public const DOMAIN_NOT_AVAILABLE_STATUS_BY_CREATED_DATE_OR_EXPIRY_DATE_OR_NS_NO_KEYWORD = 19;

    /**
     * @param  string  $whoisPlainText
     *
     * @return Whois
     */
    public function convertToWhoisObject(string $whoisPlainText): Whois
    {
        $whoisObject = new Whois();

        //reformant Whois Plain Text before explode it to strings
        $whoisPlainText = $this->reformatWhoisPlainText($whoisPlainText);
        $whoisStrings   = explode($this->eol, $whoisPlainText);
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
            if ($whoisObject->updateDate === null) {
                $whoisObject->updateDate = $this->parseUpdateDate($line);
            }

            if ($whoisObject->registryDomainId === null) {
                $whoisObject->registryDomainId = $this->parseRegistryDomainId($line);
            }

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
        /** @var array $errors list of errors */
        $errors = null;
        /** @var int $domainAvailableStatus id identificator of reason why I set available true or false */
        $domainAvailableStatus = self::DOMAIN_NOT_AVAILABLE_STATUS_BY_KEYWORD;
        /** @var string $foundDomainNotFoundSynonym set keyword found that means domain is available for registration */
        $foundDomainNotFoundSynonym = null;

        //reformat Whois Plain Text before explode it to strings
        $whoisPlainText = $this->reformatWhoisPlainText($whoisPlainText);
        $whoisStrings   = explode($this->eol, $whoisPlainText);

        foreach ($whoisStrings as $lineNumber => $line) {
            //if have keyword domain not found it means domain is free
            foreach ($this->domainAvailableSynonyms as $domainNotFoundSynonym) {
                if (strpos($line, $domainNotFoundSynonym) !== false) {
                    $domainAvailable            = true;
                    $foundDomainNotFoundSynonym = $domainNotFoundSynonym;
                    $domainAvailableStatus      = self::DOMAIN_AVAILABLE_STATUS_BY_KEYWORD;
                    break;
                }
            }
        }

        if ($domainAvailable === false) {
            if (!empty($whoisObject->creationDate) && !empty($whoisObject->expirationDate) && !empty($whoisObject->nameServers)) {
                $domainAvailableStatus = self::DOMAIN_NOT_AVAILABLE_STATUS_BY_CREATED_DATE_EXPIRY_DATE_NS_NO_KEYWORD;

                return [
                    'is_available' => $domainAvailable,
                    'errors'       => $errors,
                    'status'       => $domainAvailableStatus,
                ];
            }

            if (!empty($whoisObject->creationDate) || !empty($whoisObject->expirationDate) || !empty($whoisObject->nameServers)) {
                $domainAvailableStatus = self::DOMAIN_NOT_AVAILABLE_STATUS_BY_CREATED_DATE_OR_EXPIRY_DATE_OR_NS_NO_KEYWORD;

                return [
                    'is_available' => $domainAvailable,
                    'errors'       => $errors,
                    'status'       => $domainAvailableStatus,
                ];
            }
        }

        try {
            if ($domainAvailable === true) {
                if (!empty($whoisObject->creationDate) && !empty($whoisObject->expirationDate) && !empty($whoisObject->nameServers)) {
                    $domainAvailableStatus = self::DOMAIN_NOT_AVAILABLE_STATUS_BY_CREATED_DATE_EXPIRY_DATE_NS_WITH_KEYWORD;
                    throw new RuntimeException(
                        'Found phrase "'.$foundDomainNotFoundSynonym.'" that domain free but domain creation date, expiry date and ns exist'
                    );
                }

                if (!empty($whoisObject->creationDate)) {
                    $domainAvailableStatus = self::DOMAIN_NOT_AVAILABLE_STATUS_BY_CREATED_DATE;
                    throw new RuntimeException(
                        'Found phrase "'.$foundDomainNotFoundSynonym.'" that domain free but domain creation date exists'
                    );
                }

                if (!empty($whoisObject->expirationDate)) {
                    $domainAvailableStatus = self::DOMAIN_NOT_AVAILABLE_STATUS_BY_EXPIRY_DATE;
                    throw new RuntimeException(
                        'Found phrase "'.$foundDomainNotFoundSynonym.'" that domain free but domain expiration date exists.'
                    );
                }

                if (!empty($whoisObject->nameServers)) {
                    $domainAvailableStatus = self::DOMAIN_NOT_AVAILABLE_STATUS_BY_NS;
                    throw new RuntimeException(
                        'Found phrase "'.$foundDomainNotFoundSynonym.'" that domain free but domain nameServers is not empty.'
                    );
                }

                if (!empty($whoisObject->registrar)) {
                    $domainAvailableStatus = self::DOMAIN_NOT_AVAILABLE_STATUS_BY_REGISTRAR;
                    throw new RuntimeException(
                        'Found phrase "'.$foundDomainNotFoundSynonym.'" that domain free but domain has registrar.'
                    );
                }

                if (!empty($whoisObject->registryDomainId)) {
                    $domainAvailableStatus = self::DOMAIN_NOT_AVAILABLE_STATUS_BY_DOMAIN_ID;
                    throw new RuntimeException(
                        'Found phrase "'.$foundDomainNotFoundSynonym.'" that domain free but domain has registryDomainId.'
                    );
                }
            }
        } catch (RuntimeException $exception) {
            $domainAvailable = false;
            $errors[]        = $exception->getMessage().' Availability was switched to false.';
        }

        if (empty($whoisObject->expirationDate) && empty($whoisObject->updateDate) && empty($whoisObject->nameServers)) {
            if ($domainAvailable === false) {
                $domainAvailableStatus = self::DOMAIN_NOT_AVAILABLE_STATUS_BY_NO_DATA_PARSED;
                $errors[]              = 'Updated date, Expiration date and NS are not parsed. No phrase that domain is free';
            } else {
                $domainAvailableStatus = self::DOMAIN_AVAILABLE_STATUS_BY_KEYWORD_CREATION_DATE_EXPIRY_DATE;
                $errors[]              = 'Updated date, Expiration date and NS are not parsed. Phrase that domain is free found: "'.$foundDomainNotFoundSynonym.'"';
            }
        }

        return [
            'is_available' => $domainAvailable,
            'errors'       => $errors,
            'status'       => $domainAvailableStatus,
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
                foreach ($this->unnecessaryWords as $unnecessaryWord) {
                    if (stripos($whoisString, $unnecessaryWord) !== false) {
                        $whoisString = trim(str_ireplace($unnecessaryWord, '', $whoisString));
                    }
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
                foreach ($this->unnecessaryWords as $unnecessaryWord) {
                    if (stripos($whoisString, $unnecessaryWord) !== false) {
                        $whoisString = trim(str_ireplace($unnecessaryWord, '', $whoisString));
                    }
                }
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
                foreach ($this->unnecessaryWords as $unnecessaryWord) {
                    if (stripos($whoisString, $unnecessaryWord) !== false) {
                        $whoisString = trim(str_ireplace($unnecessaryWord, '', $whoisString));
                    }
                }
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
