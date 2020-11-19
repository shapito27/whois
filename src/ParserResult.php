<?php


namespace Shapito27\Whois;

use RuntimeException;

/**
 * Class ParserResult
 * @package Shapito27\Whois
 */
class ParserResult
{
    /** @var Whois */
    protected $whois;
    /** @var bool */
    protected $isDomainAvailable;
    /** @var null|string */
    protected $errorMessage;

    /**
     * @return Whois
     */
    public function getWhois(): Whois
    {
        if ($this->whois === null) {
            throw new RuntimeException('Whois is not set.');
        }

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
        return $this->errorMessage ?? '';
    }

    /**
     * @param  string  $errorMessage
     */
    public function setErrorMessage(string $errorMessage): void
    {
        $this->errorMessage = $errorMessage;
    }
}