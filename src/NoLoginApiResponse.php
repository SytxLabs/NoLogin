<?php

namespace SytxLabs\NoLogin;

readonly class NoLoginApiResponse
{
    public ?string $email;
    public ?string $username;
    public ?string $avatar;
    public ?string $salutation;
    public ?string $title;
    public ?string $language; // (en_GB, de_DE, etc.) ISO 639-1 language code

    public function __construct(
        ?string $email = null,
        ?string $username = null,
        ?string $avatar = null,
        ?string $salutation = null,
        ?string $title = null,
        ?string $language = null
    ) {
        $this->email = $email;
        $this->username = $username;
        $this->avatar = $avatar;
        $this->salutation = $salutation;
        $this->title = $title;
        $this->language = $language;
    }
}
