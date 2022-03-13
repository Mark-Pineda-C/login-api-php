<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit5e6382ea77b1d1847c76bcf9390d863f
{
    public static $prefixLengthsPsr4 = array (
        'F' => 
        array (
            'Firebase\\JWT\\' => 13,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Firebase\\JWT\\' => 
        array (
            0 => __DIR__ . '/..' . '/firebase/php-jwt/src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit5e6382ea77b1d1847c76bcf9390d863f::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit5e6382ea77b1d1847c76bcf9390d863f::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInit5e6382ea77b1d1847c76bcf9390d863f::$classMap;

        }, null, ClassLoader::class);
    }
}
