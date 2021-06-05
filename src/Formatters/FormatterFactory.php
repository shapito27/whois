<?php

namespace Shapito27\Whois\Formatters;

class FormatterFactory
{
    /**
     * First Factory looking for public suffix of domain, if related file exists It will use it.
     * For example for world.com It is looking for COM.php
     * if there is no COM.php it will use BaseFormatter.php
     * If you define '.br' => 'com.br' it will use COMBR.php for domains
     * which public suffixes ends with .br like .com.br, .org.br and etc.
     */
    public static $similarZones = [
        'ac.uk' => 'uk',
        '.il'   => 'il',
        '.br'   => 'com.br',
        '.be'   => 'be',
        '.si'   => 'si',
        '.kr'   => 'kr',
        '.it'   => 'it',
    ];

    /**
     * @param  string|null  $domainZone
     *
     * @return AbstractFormatter
     */
    public static function create(string $domainZone = null): AbstractFormatter
    {
        if ($domainZone === null) {
            return new BaseFormatter();
        }

        foreach (self::$similarZones as $pattern => $destinationZone) {
            if (strpos($domainZone, $pattern) !== false) {
                $domainZone = self::$similarZones[$pattern];
            }
        }

        //from co.uk to couk
        if (strpos($domainZone, '.')) {
            $domainZone = str_replace('.', '', $domainZone);
        }

        $newFormatter = '\Shapito27\Whois\Formatters\\'.strtoupper($domainZone);
        if (!class_exists($newFormatter)) {
            return new BaseFormatter();
        }

        return new $newFormatter;
    }
}