<?php

namespace Shapito27\Whois;

use Carbon\Carbon;
use Carbon\Exceptions\InvalidFormatException;
use Exception;
use RuntimeException;

/**
 * Class WhoisParser
 * @package Shapito27\Whois
 */
class WhoisParser
{
    /** @var string */
    private $domainName;

   /** @var string */
    private $whoisText;

    /** @var string */
    private $dateFormat = self::DEFAULT_DATE_FORMAT;

    private $creationDateSynonyms = [
        'created............:',
        'Domain record activated:',
        'domain_dateregistered:',
        'record created:',
        'Creation Date:',
        'created:',
        'Registered on:',
        'Registered:',
        'Registration Time:',
        '[最終更新]',
        '[接続年月日]',
        '[登録年月日]',
    ];

    private $updateDateSynonyms = [
        'Domain record last updated:',
        'domain_datelastmodified:',
        'Last updated date:',
        'modified...........:',
        '[Last Update]',
        'Updated Date:',
        'Last updated:',
        'Last Modified:',
        'modified:',
        'changed:', //be careful. Could be wrong match for .org.il, .gov.il
        '[最終更新]',
    ];


    private $expiryDateSynonyms = [
        'expires............:',
        'Registry Expiry Date:',
        'option expiration date:',
        'Expiration date:',
        'Domain expires:',
        'Expiry date:',
        'Expire Date:',
        'Expiration Time:',
        'paid-till:',
        'Expires On:',
        'expires:',
        '[有効期限]',
    ];

    private $nameServerSynonyms = [
        'nserver............:',
        'Name Server:',
        'Nameserver:',
        'nserver:',
        'Name servers:',
        'Hostname:',
        'p. [ネームサーバ]',
        'ns_name_01:',
        'ns_name_02:',
        'ns_name_03:',
        'ns_name_04:',
        '[Name Server]',
    ];

    private $registrarSynonyms = [
        'registrar..........:',
        '[Registrant]',
        'registrar_name:',
        'Registrar Name:',
        'Registrar:',
    ];

    private $registrarIanaId = [
        'Registrar IANA ID:',
    ];

    private $registryDomainIdSynonyms = [
        'register number....:',
        'Registry Domain ID:',
    ];

    private $registrarAbuseContactEmailSynonyms = [
        'Registrar Abuse Contact Email:',
    ];

    private $registrarAbuseContactPhoneSynonyms = [
        'Registrar Abuse Contact Phone:',
    ];

    private $domainNotFoundSynonyms = [
        'No records matching',
        'not have an entry',
        'no existe',
        'No Matches',
        'No domain records were found to match',
        'Not Registered',
        'not found in our database',
        'nije registrirana',
        '% Not Registered',
        'was not found',
        'but this server does not have',
        'AVAILABLE',
        'do not have an entry in our database matching your query',
        'Status:			available',
        'Status: free',
        'Invalid query or domain name not known',
        'is free',
        'nothing found',
        'No match!!',
        'not exist',
        'DOMINIO NO REGISTRADO',
        'No data was found',
        'No domains matched',
        'Object_Not_Found',
        'does not exist',
        'No match found',
        'Domain not registered',
        'Requested Domain cannot be found',
        'Status: Not Registered',
        'Domain unknown',
        'is available for',
        'no match',
        'is not registered',
        '%ERROR:103',
        '220 Available',
        'not found',
        'is available for purchase',
        'Status: AVAILABLE',
        'has no matches',
        'no entries found',
        'is available',
        'No Found',
        'NO MATCH',
        'Not found',
        'No Object Found',
        'is still available',
        'Domain not found',
        'is not valid!',
        'This domain name has not been registered.',
        'No information available',
        'Not found:',
        '% No match',
        'Above domain name is not registered to',
        'Nothing found for this query.',
        '% no matching objects found',
        'The domain has not been registered',
        'NO OBJECT FOUND!',
        '% No entries found.',
        'No Match',
        'does not exist in database',
        'Not Found.',
        'No Data Found',
        'No match',
        'Domain Not Found',
        'Available',
        'Not find MatchingRecord',
        'NOT FOUND',
        'is available for registration',
        'No entries found',
        'DOMAIN NOT FOUND',
        'No such domain',
        'no matching record',
        'No match for',
        'Domain Status: No Object Found',
        'Domain not found.',
        'not found...',
    ];

    private $unnecessaryWord = 'before';

    public const DEFAULT_DATE_FORMAT = 'Y-m-d H:i:s';

    /**
     * WhoisParser constructor.
     *
     * @param  string  $domainName
     * @param  string  $whoisText
     */
    public function __construct(string $domainName, string $whoisText)
    {
        $this->domainName = $domainName;
        $this->whoisText = $whoisText;
    }

    /**
     * @return ParserResult
     */
    public function run(): ParserResult
    {
        $foundDomainNotFoundSynonym = null;
        $parseUpdateInfo = true;

        $parserResult = new ParserResult();
        $parserResult->setIsDomainAvailable(false);
        $whoisObject         = new Whois();

        /**
         * check if domain zone ends with .il
         * @todo for .il do investigation. It has a lot of lines with keyword "changed:"
         * changed:      registrar AT ns.il 19980219 (Changed)\n
         * changed:      domain-registrar AT isoc.org.il 20080110 (Changed)\n
         * changed:      domain-registrar AT isoc.org.il 20111027 (Assigned)\n
         * changed:      Managing Registrar 20111027\n
         */
        if(preg_match('~\.il$~', $this->getDomainName(), $matches) === 1) {
            $parseUpdateInfo = false;
        }

        try {
            $info = $this->whoisText;

            $whoisStrings = explode("\n", $info);

            foreach ($whoisStrings as $lineNumber => $line) {
                if ($whoisObject->creationDate === null) {
                    //looking for creation date
                    foreach ($this->creationDateSynonyms as $creationDateSynonym) {
                        if (stripos($line, $creationDateSynonym) !== false) {
                            if (strpos($line, $this->unnecessaryWord) !== false) {
                                $line = str_replace($this->unnecessaryWord, '', $line);
                            }
                            $creationDate = trim(str_ireplace($creationDateSynonym, '', $line));
                            if (!empty($creationDate)) {
                                $whoisObject->creationDate = $this->parseDate($creationDate);
                                break;
                            }
                        }
                    }
                }

                //looking for expiry date
                if ($whoisObject->expirationDate === null) {
                    foreach ($this->expiryDateSynonyms as $expiryDateSynonym) {
                        if (stripos($line, $expiryDateSynonym) !== false) {
                            $expirationDate = trim(str_ireplace($expiryDateSynonym, '', $line));
                            if (!empty($expirationDate)) {
                                $whoisObject->expirationDate = $this->parseDate($expirationDate);
                                break;
                            }
                        }
                    }
                }

                //looking for updated date
                if ($parseUpdateInfo && $whoisObject->updateDate === null) {
                    foreach ($this->updateDateSynonyms as $updateDateSynonym) {
                        if (stripos($line, $updateDateSynonym) !== false) {
                            $updateDate = trim(str_ireplace($updateDateSynonym, '', $line));
                            if (!empty($updateDate)) {
                                $whoisObject->updateDate = $this->parseDate($updateDate);
                                break;
                            }
                        }
                    }
                }

                foreach ($this->registryDomainIdSynonyms as $registryDomainIdSynonym) {
                    if (stripos($line, $registryDomainIdSynonym) !== false) {
                        $registryDomainId = trim(str_ireplace($registryDomainIdSynonym, '', $line));
                        if (!empty($registryDomainId)) {
                            $whoisObject->registryDomainId = $registryDomainId;
                            break;
                        }
                    }
                }

                foreach ($this->registrarSynonyms as $registrarSynonym) {
                    if ((stripos($line, $registrarSynonym) !== false)) {
                        $registrarName = trim(str_ireplace($registrarSynonym, '', $line));
                        if (!empty($registrarName)) {
                            if ($whoisObject->registrar === null) {
                                $whoisObject->registrar = new Registrar();
                            }
                            $whoisObject->registrar->name = $registrarName;
                            break;
                        }
                    }
                }

                foreach ($this->registrarIanaId as $registrarIanaId) {
                    if (stripos($line, $registrarIanaId) !== false) {
                        $registrarId = trim(str_ireplace($registrarIanaId, '', $line));
                        if (!empty($registrarId)) {
                            if ($whoisObject->registrar === null) {
                                $whoisObject->registrar = new Registrar();
                            }
                            $whoisObject->registrar->id = $registrarId;
                            break;
                        }
                    }
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

                foreach ($this->domainNotFoundSynonyms as $domainNotFoundSynonym) {
                    if (strpos($line, $domainNotFoundSynonym) !== false) {
                        $parserResult->setIsDomainAvailable(true);
                        $foundDomainNotFoundSynonym = $domainNotFoundSynonym;
                        break;
                    }
                }
            }

            $parserResult->setWhois($whoisObject);

            try {
                if ($parserResult->isDomainAvailable()) {
                    if ($whoisObject->expirationDate !== null) {
                        $expirationDate = $this->parseDate($whoisObject->expirationDate);
                        $today          = Carbon::now();
                        if ($today->lessThan($expirationDate)) {
                            throw new RuntimeException(
                                'Found phrase that domain free but parsed expiration date in the future. Found phrase: '
                                .$foundDomainNotFoundSynonym
                            );
                        }
                    }

                    if (!empty($whoisObject->nameServers)) {
                        throw new RuntimeException(
                            'Found phrase that domain free but domain has nameservers. Found phrase: '
                            .$foundDomainNotFoundSynonym
                        );
                    }

                    if (!empty($whoisObject->registrar)) {
                        throw new RuntimeException(
                            'Found phrase that domain free but domain has registrar. Found phrase: '
                            .$foundDomainNotFoundSynonym
                        );
                    }

                    if (!empty($parsedWhoisDataObject->registryDomainId)) {
                        throw new RuntimeException(
                            'Found phrase that domain free but domain has registryDomainId. Found phrase: '
                            .$foundDomainNotFoundSynonym
                        );
                    }
                }
            } catch (RuntimeException $exception) {
                $parserResult->setIsDomainAvailable(false);
                throw $exception;
            }

            if (empty($whoisObject->expirationDate) && empty($whoisObject->updateDate)
                && $parserResult->isDomainAvailable() === false) {
                throw new RuntimeException(
                    'Updated date and Expiration date is not parsed. No phrase that domain is not found'
                );
            }
        } catch (Exception $e) {
            $parserResult->setErrorMessage($this->getDomainName() . ' error. ' . $e->getMessage());
        }

        return $parserResult;
    }

    /**
     * @param  string  $date
     *
     * @return string
     */
    private function parseDate(string $date): string
    {
        try {
            return Carbon::parse($date)->format($this->dateFormat);
        } catch (InvalidFormatException $invalidFormatException) {
            //try to change format
            try {
                $date = str_replace('.', '-', $date);

                return Carbon::parse($date)->format($this->dateFormat);
            } catch (Exception $exception) {
                return $date;
            }
        } catch (Exception $exception) {
            return $date;
        }
    }

    /**
     * @param  string  $dateFormat
     */
    public function setDateFormat(string $dateFormat): void
    {
        $this->dateFormat = $dateFormat;
    }

    /**
     * @param  string[]  $creationDateSynonyms
     */
    public function setCreationDateSynonyms(array $creationDateSynonyms): void
    {
        $this->creationDateSynonyms = $creationDateSynonyms;
    }

    /**
     * @param  string[]  $updateDateSynonyms
     */
    public function setUpdateDateSynonyms(array $updateDateSynonyms): void
    {
        $this->updateDateSynonyms = $updateDateSynonyms;
    }

    /**
     * @param  string[]  $expiryDateSynonyms
     */
    public function setExpiryDateSynonyms(array $expiryDateSynonyms): void
    {
        $this->expiryDateSynonyms = $expiryDateSynonyms;
    }

    /**
     * @param  string[]  $nameServerSynonyms
     */
    public function setNameServerSynonyms(array $nameServerSynonyms): void
    {
        $this->nameServerSynonyms = $nameServerSynonyms;
    }

    /**
     * @param  string[]  $registrarSynonyms
     */
    public function setRegistrarSynonyms(array $registrarSynonyms): void
    {
        $this->registrarSynonyms = $registrarSynonyms;
    }

    /**
     * @param  string[]  $registrarIanaId
     */
    public function setRegistrarIanaId(array $registrarIanaId): void
    {
        $this->registrarIanaId = $registrarIanaId;
    }

    /**
     * @param  string[]  $registryDomainIdSynonyms
     */
    public function setRegistryDomainIdSynonyms(array $registryDomainIdSynonyms): void
    {
        $this->registryDomainIdSynonyms = $registryDomainIdSynonyms;
    }

    /**
     * @param  string[]  $registrarAbuseContactEmailSynonyms
     */
    public function setRegistrarAbuseContactEmailSynonyms(array $registrarAbuseContactEmailSynonyms): void
    {
        $this->registrarAbuseContactEmailSynonyms = $registrarAbuseContactEmailSynonyms;
    }

    /**
     * @param  string[]  $registrarAbuseContactPhoneSynonyms
     */
    public function setRegistrarAbuseContactPhoneSynonyms(array $registrarAbuseContactPhoneSynonyms): void
    {
        $this->registrarAbuseContactPhoneSynonyms = $registrarAbuseContactPhoneSynonyms;
    }

    /**
     * @param  string[]  $domainNotFoundSynonyms
     */
    public function setDomainNotFoundSynonyms(array $domainNotFoundSynonyms): void
    {
        $this->domainNotFoundSynonyms = $domainNotFoundSynonyms;
    }

    /**
     * @param  string  $unnecessaryWord
     */
    public function setUnnecessaryWord(string $unnecessaryWord): void
    {
        $this->unnecessaryWord = $unnecessaryWord;
    }

    /**
     * @param  string  $creationDateSynonym
     */
    public function addCreationDateSynonym(string $creationDateSynonym): void
    {
        $this->creationDateSynonyms[] = $creationDateSynonym;
    }

    /**
     * @param  string  $updateDateSynonym
     */
    public function addUpdateDateSynonym(string $updateDateSynonym): void
    {
        $this->updateDateSynonyms[] = $updateDateSynonym;
    }

    /**
     * @param  string  $expiryDateSynonym
     */
    public function addExpiryDateSynonym(string $expiryDateSynonym): void
    {
        $this->expiryDateSynonyms[] = $expiryDateSynonym;
    }

    /**
     * @param  string  $nameServerSynonym
     */
    public function addNameServerSynonym(string $nameServerSynonym): void
    {
        $this->nameServerSynonyms[] = $nameServerSynonym;
    }

    /**
     * @param  string  $registrarSynonym
     */
    public function addRegistrarSynonym(string $registrarSynonym): void
    {
        $this->registrarSynonyms[] = $registrarSynonym;
    }

    /**
     * @param  string  $registrarIanaId
     */
    public function addRegistrarIanaId(string $registrarIanaId): void
    {
        $this->registrarIanaId = $registrarIanaId;
    }

    /**
     * @param  string  $registryDomainIdSynonym
     */
    public function addRegistryDomainIdSynonym(string $registryDomainIdSynonym): void
    {
        $this->registryDomainIdSynonyms[] = $registryDomainIdSynonym;
    }

    /**
     * @param  string  $registrarAbuseContactEmailSynonym
     */
    public function addRegistrarAbuseContactEmailSynonym(string $registrarAbuseContactEmailSynonym): void
    {
        $this->registrarAbuseContactEmailSynonyms[] = $registrarAbuseContactEmailSynonym;
    }

    /**
     * @param  string  $registrarAbuseContactPhoneSynonym
     */
    public function addRegistrarAbuseContactPhoneSynonym(string $registrarAbuseContactPhoneSynonym): void
    {
        $this->registrarAbuseContactPhoneSynonyms[] = $registrarAbuseContactPhoneSynonym;
    }

    /**
     * @param  string  $domainNotFoundSynonym
     */
    public function addDomainNotFoundSynonym(string $domainNotFoundSynonym): void
    {
        $this->domainNotFoundSynonyms[] = $domainNotFoundSynonym;
    }

    /**
     * @return string
     */
    public function getDomainName(): string
    {
        return $this->domainName;
    }
}
