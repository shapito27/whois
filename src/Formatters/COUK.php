<?php

namespace Shapito27\Whois\Formatters;

class COUK extends BaseFormatter
{
    public $eol = "\n\n";

    public function __construct()
    {
        parent::__construct();

        $this->nameServerSynonyms = ['Name servers:'];
    }

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


    /**
     * @param  array  $whoisStrings
     *
     * @return array
     */
    protected function parseNameServers(array $whoisStrings): array
    {
        $nameServersList   = [];
        $keywordNSFound    = false;
        $nameServerSynonym = $this->nameServerSynonyms[0];
        //parse name servers
        foreach ($whoisStrings as $line) {
            if ((stripos($line, $nameServerSynonym) !== false)) {
                $keywordNSFound = true;
                $line           = str_replace($nameServerSynonym, '', $line);
            }
            if ($keywordNSFound === true) {
                $nsLines = explode("\n", $line);
                foreach ($nsLines as $nsLine) {
                    $nameServer = trim(str_replace(["\t", "\n"], '', $nsLine));
                    if (empty($nameServer)) {
                        continue;
                    }
                    if (in_array($nameServer, $nameServersList, true) === false) {
                        $nameServersList[] = $nameServer;
                    }
                }
                $keywordNSFound = false;
            }
        }

        return $nameServersList;
    }
}