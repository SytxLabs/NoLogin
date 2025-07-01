<?php

namespace SytxLabs\NoLogin\Encrypt;

use Exception;

class DecryptException extends Exception
{
    /**
     * EncryptException constructor.
     */
    public function __construct(string $message = 'Decryption failed')
    {
        parent::__construct($message);
    }
}
