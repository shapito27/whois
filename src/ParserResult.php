<?php


namespace Shapito27\Whois;

/**
 * Class ParserResult
 * @package Shapito27\Whois
 */
class ParserResult
{
    /** @var Whois */
    public $whois;
    /** @var bool */
    public $isDomainAvailable;
    /** @var string */
    public $errorMessage;


    public function getWhois(): Whois
    {
        return $this->whois;
    }

    /**
     * @param  Whois  $whois
     */
    public function setWhois(Whois $whois): void
    {
        $this->whois = $whois;
    }

    /**
     * @return bool
     */
    public function isDomainAvailable(): bool
    {
        return $this->isDomainAvailable;
    }

    /**
     * @param  bool  $isDomainAvailable
     */
    public function setIsDomainAvailable(bool $isDomainAvailable): void
    {
        $this->isDomainAvailable = $isDomainAvailable;
    }

    /**
     * @return string
     */
    public function getErrorMessage(): string
    {
        return $this->errorMessage;
    }

    /**
     * @param  string  $errorMessage
     */
    public function setErrorMessage(string $errorMessage): void
    {
        $this->errorMessage = $errorMessage;
    }
}