<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInit556325df05703ed685d38b2add6c2508
{
    public static $files = array (
        '253c157292f75eb38082b5acb06f3f01' => __DIR__ . '/..' . '/nikic/fast-route/src/functions.php',
        '5255c38a0faeba867671b61dfda6d864' => __DIR__ . '/..' . '/paragonie/random_compat/lib/random.php',
    );

    public static $prefixLengthsPsr4 = array (
        'S' => 
        array (
            'Slim\\' => 5,
            'SimpleCrud\\' => 11,
        ),
        'P' => 
        array (
            'Psr\\Http\\Message\\' => 17,
            'Psr\\Container\\' => 14,
        ),
        'I' => 
        array (
            'Interop\\Container\\' => 18,
        ),
        'F' => 
        array (
            'FastRoute\\' => 10,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Slim\\' => 
        array (
            0 => __DIR__ . '/..' . '/slim/slim/Slim',
        ),
        'SimpleCrud\\' => 
        array (
            0 => __DIR__ . '/..' . '/simple-crud/simple-crud/src',
        ),
        'Psr\\Http\\Message\\' => 
        array (
            0 => __DIR__ . '/..' . '/psr/http-message/src',
        ),
        'Psr\\Container\\' => 
        array (
            0 => __DIR__ . '/..' . '/psr/container/src',
        ),
        'Interop\\Container\\' => 
        array (
            0 => __DIR__ . '/..' . '/container-interop/container-interop/src/Interop/Container',
        ),
        'FastRoute\\' => 
        array (
            0 => __DIR__ . '/..' . '/nikic/fast-route/src',
        ),
    );

    public static $prefixesPsr0 = array (
        'P' => 
        array (
            'Pimple' => 
            array (
                0 => __DIR__ . '/..' . '/pimple/pimple/src',
            ),
        ),
        'H' => 
        array (
            'Httpful' => 
            array (
                0 => __DIR__ . '/..' . '/nategood/httpful/src',
            ),
        ),
    );

    public static $classMap = array (
        'Defuse\\Crypto\\Core' => __DIR__ . '/..' . '/defuse/php-encryption/src/Core.php',
        'Defuse\\Crypto\\Crypto' => __DIR__ . '/..' . '/defuse/php-encryption/src/Crypto.php',
        'Defuse\\Crypto\\DerivedKeys' => __DIR__ . '/..' . '/defuse/php-encryption/src/DerivedKeys.php',
        'Defuse\\Crypto\\Encoding' => __DIR__ . '/..' . '/defuse/php-encryption/src/Encoding.php',
        'Defuse\\Crypto\\Exception\\BadFormatException' => __DIR__ . '/..' . '/defuse/php-encryption/src/Exception/BadFormatException.php',
        'Defuse\\Crypto\\Exception\\CryptoException' => __DIR__ . '/..' . '/defuse/php-encryption/src/Exception/CryptoException.php',
        'Defuse\\Crypto\\Exception\\EnvironmentIsBrokenException' => __DIR__ . '/..' . '/defuse/php-encryption/src/Exception/EnvironmentIsBrokenException.php',
        'Defuse\\Crypto\\Exception\\IOException' => __DIR__ . '/..' . '/defuse/php-encryption/src/Exception/IOException.php',
        'Defuse\\Crypto\\Exception\\WrongKeyOrModifiedCiphertextException' => __DIR__ . '/..' . '/defuse/php-encryption/src/Exception/WrongKeyOrModifiedCiphertextException.php',
        'Defuse\\Crypto\\File' => __DIR__ . '/..' . '/defuse/php-encryption/src/File.php',
        'Defuse\\Crypto\\Key' => __DIR__ . '/..' . '/defuse/php-encryption/src/Key.php',
        'Defuse\\Crypto\\KeyOrPassword' => __DIR__ . '/..' . '/defuse/php-encryption/src/KeyOrPassword.php',
        'Defuse\\Crypto\\KeyProtectedByPassword' => __DIR__ . '/..' . '/defuse/php-encryption/src/KeyProtectedByPassword.php',
        'Defuse\\Crypto\\RuntimeTests' => __DIR__ . '/..' . '/defuse/php-encryption/src/RuntimeTests.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInit556325df05703ed685d38b2add6c2508::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInit556325df05703ed685d38b2add6c2508::$prefixDirsPsr4;
            $loader->prefixesPsr0 = ComposerStaticInit556325df05703ed685d38b2add6c2508::$prefixesPsr0;
            $loader->classMap = ComposerStaticInit556325df05703ed685d38b2add6c2508::$classMap;

        }, null, ClassLoader::class);
    }
}
