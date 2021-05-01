<?php

namespace Shapito27\Whois\Formatters;

class FormatterFactory
{
    //domain zones which use similar format.
    public static $similarZones = [
        'ac.uk' => 'uk',
        '.il' => 'il',
        '.br' => 'com.br',
        '.be' => 'be',
        '.si' => 'si',
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
        if(strpos($domainZone, '.')) {
            $domainZone = str_replace('.', '', $domainZone);
        }

        $newFormatter = '\Shapito27\Whois\Formatters\\' . strtoupper($domainZone);
        if (!class_exists($newFormatter)) {
            return new BaseFormatter();
        }

        return new $newFormatter;
    }
}