<?php

namespace SytxLabs\NoLogin;

enum Scope: string
{
    case Email = 'email';
    case Username = 'username';
    case Avatar = 'avatar';
    case Salutation = 'salutation';
    case Title = 'title';
    case Language = 'language';

    public static function defaultScopes(): array
    {
        return [
            self::Email->value,
            self::Username->value,
            self::Language->value,
        ];
    }
}
