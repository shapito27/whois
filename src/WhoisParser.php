<?php

namespace Shapito27\Whois;

use Exception;
use Shapito27\Whois\Formatters\AbstractFormatter;
use Shapito27\Whois\Formatters\FormatterFactory;

/**
 * Class WhoisParser
 * @package Shapito27\Whois
 */
class WhoisParser
{
    /** @var string|null */
    private $domainName;
    /** @var string|null */
    private $domainPublicSuffix;

    /** @var string|null */
    private $whoisText;

    private $formatter;

    /**
     * WhoisParser constructor.
     *
     * @param  string  $domainName
     * @param  string  $whoisText
     */
    public function __construct(string $domainName = null, string $whoisText = null, $formatter = null)
    {
        if ($domainName !== null) {
            $this->setDomainName($domainName);
        }

        if ($whoisText !== null) {
            $this->setWhoisText($whoisText);
        }
    }

    /**
     * @return ParserResult
     */
    public function run(): ParserResult
    {
        $parserResult = new ParserResult();
        $parserResult->setIsDomainAvailable(false);

        try {
            $formatter = $this->getFormatter();
            $whoisObject = $formatter->convertToWhoisObject($this->whoisText);
            $isDomainAvailableResult = $formatter->isDomainAvailable($this->whoisText, $whoisObject);
            $parserResult->setIsDomainAvailable($isDomainAvailableResult['is_available']);
            if (isset($isDomainAvailableResult['errors'])) {
                $parserResult->setErrorMessage(implode('. ', $isDomainAvailableResult['errors']));
            }
            $parserResult->setWhois($whoisObject);
        } catch (Exception $e) {
            $errorMessage = $e->getMessage();
            while ($e->getPrevious() !== null) {
                $e            = $e->getPrevious();
                $errorMessage .= $e->getMessage();
            }
            $parserResult->setErrorMessage($errorMessage);
        }

        return $parserResult;
    }

    /**
     * @return string
     */
    public function getDomainName(): ?string
    {
        return $this->domainName;
    }

    /**
     * @param  string  $domainName
     */
    public function setDomainName(string $domainName): void
    {
        $this->domainName = $domainName;
        if ($domainName !== null && ($pos = strpos($domainName, '.')) !== false) {
            $this->setDomainPublicSuffix(substr($domainName,$pos+1));
        }
    }

    /**
     * @return string
     */
    public function getDomainPublicSuffix(): ?string
    {
        return $this->domainPublicSuffix;
    }

    /**
     * @param  string  $domainPublicSuffix
     */
    public function setDomainPublicSuffix(string $domainPublicSuffix): void
    {
        $this->domainPublicSuffix = $domainPublicSuffix;
    }

    /**
     * @param  string  $whoisText
     */
    public function setWhoisText(string $whoisText): void
    {
        $this->whoisText = $whoisText;
    }

    /**
     * @return AbstractFormatter|null
     * @throws Exception
     */
    public function getFormatter(): ?AbstractFormatter
    {
        if($this->formatter === null && empty($this->getDomainName())) {
            throw new Exception('Can\'t set Formatter automatically because domain name is not set');
        }

        //set formatter by domain public suffix
        if($this->formatter === null) {
            $this->setFormatter(FormatterFactory::create($this->getDomainPublicSuffix()));
        }

        return $this->formatter;
    }

    /**
     * @param  string  $domainName
     */
    public function setFormatter($formatter): void
    {
        $this->formatter = $formatter;
    }

    /**
     * @throws Exception
     */
    public function detectFormat(): void
    {
        if(empty($this->getDomainName())) {
            throw new Exception('Can\'t set Formatter automatically because domain name is not set');
        }

        //set formatter by domain public suffix
        $this->setFormatter(FormatterFactory::create($this->getDomainPublicSuffix()));
    }
}
