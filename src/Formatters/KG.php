<?php

namespace Shapito27\Whois\Formatters;

use Shapito27\Whois\Registrar;
use Shapito27\Whois\Whois;

class KG extends BaseFormatter
{
    public function __construct()
    {
        parent::__construct();

        $this->setUpdateDateSynonyms(['Record last updated on:']);
        $this->setExpiryDateSynonyms(['Record expires on:']);
        $this->setNameServerSynonyms(['Name servers in the listed order:']);
    }

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

            /**
             * Custom search of nameservers
             */
            $keywordNSFound = false;
            //parse name servers
            foreach ($whoisStrings as $whoisLine) {
                if ($whoisLine !== "\n" && $keywordNSFound === true) {
                    if (in_array($whoisLine, $whoisObject->nameServers, true) === false) {
                        $whoisObject->nameServers[] = $whoisLine;
                    }
                } elseif (($whoisLine === "\n" && $keywordNSFound === true)) {
                    break;
                } elseif ($keywordNSFound === false) {
                    foreach ($this->nameServerSynonyms as $nameServerSynonym) {
                        if ((stripos($whoisLine, $nameServerSynonym) !== false)) {
                            $keywordNSFound = true;
                            break;
                        }
                    }
                }
            }
        }

        return $whoisObject;
    }
}