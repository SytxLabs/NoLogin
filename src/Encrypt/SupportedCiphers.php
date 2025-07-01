<?php

namespace SytxLabs\NoLogin\Encrypt;

enum SupportedCiphers: string
{
    case AES_128_CBC = 'AES-128-CBC';
    case AES_256_CBC = 'AES-256-CBC';
    case AES_128_GCM = 'AES-128-GCM';
    case AES_256_GCM = 'AES-256-GCM';

    public function size(): int
    {
        return match ($this) {
            self::AES_128_CBC, self::AES_128_GCM => 16,
            self::AES_256_CBC, self::AES_256_GCM => 32,
        };
    }

    public function aead(): bool
    {
        return match ($this) {
            self::AES_128_GCM, self::AES_256_GCM => true,
            default => false,
        };
    }
}
