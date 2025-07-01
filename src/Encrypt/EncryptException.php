<?php

namespace SytxLabs\NoLogin\Encrypt;

use Exception;

class EncryptException extends Exception
{
    /**
     * EncryptException constructor.
     */
    public function __construct(string $message = 'Encryption failed')
    {
        parent::__construct($message);
    }
}
