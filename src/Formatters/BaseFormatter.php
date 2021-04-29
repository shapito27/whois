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

//        //@todo move it to ILFormatter
//        /**
//         * check if domain zone ends with .il
//         * @todo for .il do investigation. It has a lot of lines with keyword "changed:"
//         * changed:      registrar AT ns.il 19980219 (Changed)\n
//         * changed:      domain-registrar AT isoc.org.il 20080110 (Changed)\n
//         * changed:      domain-registrar AT isoc.org.il 20111027 (Assigned)\n
//         * changed:      Managing Registrar 20111027\n
//         */
//        if (preg_match('~\.il$~', $this->getDomainName(), $matches) === 1) {
//            $parseUpdateInfo = false;
//        }

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

        $whoisStrings = explode($this->eol, $whoisPlainText);

        foreach ($whoisStrings as $lineNumber => $line) {
            //if have keyword domain not found it means domain is free
            foreach ($this->domainNotFoundSynonyms as $domainNotFoundSynonym) {
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
}