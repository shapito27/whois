<?php

namespace Shapito27\Whois\Formatters;

use Shapito27\Whois\Registrar;
use Shapito27\Whois\Whois;

class IT extends BaseFormatter
{
    public function __construct()
    {
        parent::__construct();

        $this->setUpdateDateSynonyms(['Last Update:']);
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
            if ($whoisObject->updateDate === null) {
                $whoisObject->updateDate = $this->parseUpdateDate($line);
            }
        }

        $keywordNSFound = false;
        $nameServer     = null;
        //parse name servers
        foreach ($whoisStrings as $lineNumber => $line) {
            if ((stripos($line, 'Keys:') === false) && $keywordNSFound === true) {
                $nameServer = trim(str_replace(["\t", "\n"], '', $line));
                if (in_array($nameServer, $whoisObject->nameServers, true) === false) {
                    $whoisObject->nameServers[] = $nameServer;
                }
            } elseif (($line === "\n") && $keywordNSFound === true) {
                break;
            }
            if ((stripos($line, 'Nameservers') !== false)) {
                $keywordNSFound = true;
            }
        }

        $keywordRegistrarFound = false;
        $registrarName         = null;
        //parse registrar name
        foreach ($whoisStrings as $lineNumber => $line) {
            if ((stripos($line, 'Name:') !== false) && $keywordRegistrarFound === true) {
                $registrarName = trim(str_replace(["Name:"], '', $line));
            }
            if ((stripos($line, 'Registrar') !== false)) {
                $keywordRegistrarFound = true;
            }


            if ($whoisObject->registrar === null && $registrarName !== null) {
                $whoisObject->registrar       = new Registrar();
                $whoisObject->registrar->name = $registrarName;
                break;
            }
        }

        return $whoisObject;
    }
}