<?php

namespace SytxLabs\NoLogin\Encrypt;

use Exception;
use JsonException;

use function openssl_decrypt;
use function openssl_encrypt;

use Random\RandomException;
use RuntimeException;
use SensitiveParameter;

class Encrypter
{
    private string $key;
    private string $cipher;
    private bool $aead;

    public function __construct(string $key, array|string|SupportedCiphers $cipher = 'aes-128-cbc')
    {
        if (($k = base64_decode($key, true)) !== false) {
            $key = $k;
        }
        if (! static::supported($key, $cipher)) {
            throw new RuntimeException('Unsupported cipher or incorrect key length. Supported ciphers are: ' . implode(', ', array_map(static fn ($s) => $s->value, SupportedCiphers::cases())) . '.');
        }

        $this->key = $key;
        $supportedCipher = is_string($cipher) ? SupportedCiphers::tryFrom(strtoupper($cipher)) : $cipher;
        if ($supportedCipher instanceof SupportedCiphers) {
            $this->cipher = strtolower($supportedCipher->value);
            $this->aead = $supportedCipher->aead();
        } elseif (is_array($cipher) && isset($cipher['aead'], $cipher['cipher'])) {
            $this->cipher = strtolower($cipher['cipher']);
            $this->aead = $cipher['aead'];
        } else {
            throw new RuntimeException('Unsupported cipher or incorrect key length.');
        }
    }

    /**
     * Determine if the given key and cipher combination is valid.
     *
     * @param  string|SupportedCiphers|array{cipher: string, size: int, aead: bool} $cipher
     */
    public static function supported(string $key, array|string|SupportedCiphers $cipher): bool
    {
        $supportedCipher = null;
        if (is_string($cipher)) {
            $supportedCipher = SupportedCiphers::tryFrom(strtoupper($cipher));
        } elseif ($cipher instanceof SupportedCiphers) {
            $supportedCipher = $cipher;
        } elseif (is_array($cipher) && isset($cipher['cipher'])) {
            $supportedCipher = strtolower($cipher['cipher']);
            if (!in_array($supportedCipher, openssl_get_cipher_methods(), true)) {
                return false;
            }
        }
        $size = $supportedCipher?->size() ?? $cipher['size'] ?? null;
        $aead = $supportedCipher?->aead() ?? $cipher['aead'] ?? null;
        if ($supportedCipher === null || $size === null || $aead === null) {
            return false;
        }
        return mb_strlen($key, '8bit') === $size;
    }

    /**
     * Create a new encryption key for the given cipher.
     */
    public static function generateKey(string|SupportedCiphers $cipher): string
    {
        try {
            return random_bytes((is_string($cipher) ? SupportedCiphers::tryFrom(strtoupper($cipher))?->size() : $cipher->size()) ?? 32);
        } catch (Exception|RandomException $e) {
            throw new RuntimeException('Could not generate a random key: ' . $e->getMessage());
        }
    }

    /**
     * Encrypt the given value.
     *
     * @throws EncryptException
     */
    public function encrypt(#[SensitiveParameter] mixed $value, bool $serialize = true): string
    {
        try {
            $iv = random_bytes(openssl_cipher_iv_length(strtolower($this->cipher)));
        } catch (RandomException $e) {
            throw new RuntimeException('Could not generate a random IV: ' . $e->getMessage());
        }

        $value = openssl_encrypt($serialize ? serialize($value) : $value, strtolower($this->cipher), $this->key, 0, $iv, $tag);

        if ($value === false) {
            throw new EncryptException('Could not encrypt the data.');
        }

        $iv = base64_encode($iv);
        $tag = base64_encode($tag ?? '');

        $mac = $this->aead ? '' : $this->hash($iv, $value, $this->key);
        try {
            $json = json_encode(compact('iv', 'value', 'mac', 'tag'), JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        } catch (JsonException $e) {
            throw new EncryptException('Could not encrypt the data: ' . $e->getMessage());
        }
        return base64_encode(base64_encode(base64_encode($json) . '|' . hash('sha512', $json)));
    }

    /**
     * Encrypt a string without serialization.
     *
     * @throws EncryptException
     */
    public function encryptString(#[SensitiveParameter] string $value): string
    {
        return $this->encrypt($value, false);
    }

    /**
     * Decrypt the given value.
     *
     * @throws DecryptException
     */
    public function decrypt(#[SensitiveParameter] string $payload, bool $unserialize = true, array $unserializeOptions = []): mixed
    {
        $payloadArray = $this->getJsonPayload($payload);
        $iv = base64_decode($payloadArray['iv']);
        $this->ensureTagIsValid($tag = empty($payloadArray['tag']) ? null : base64_decode($payloadArray['tag']));

        if ($this->shouldValidateMac() && !$this->validMacForKey($payloadArray, $this->key)) {
            throw new DecryptException('The MAC is invalid.');
        }
        $decrypted = openssl_decrypt($payloadArray['value'], strtolower($this->cipher), $this->key, 0, $iv, $tag ?? '');

        if ($decrypted === false) {
            throw new DecryptException('Could not decrypt the data.');
        }

        return $unserialize ? unserialize($decrypted, $unserializeOptions) : $decrypted;
    }

    /**
     * Decrypt the given string without unserialization.
     *
     * @throws DecryptException
     */
    public function decryptString(#[SensitiveParameter] string $payload): string
    {
        return (string) $this->decrypt($payload, false)->__toString();
    }

    /**
     * Create a MAC for the given value.
     */
    protected function hash(#[SensitiveParameter] string $iv, #[SensitiveParameter] mixed $value, #[SensitiveParameter] string $key): string
    {
        return hash_hmac('sha256', $iv.$value, $key);
    }

    /**
     * Get the JSON array from the given payload.
     *
     * @throws DecryptException
     */
    protected function getJsonPayload(string $payload): array
    {
        $payload = base64_decode($payload);
        if ($payload === false) {
            throw new DecryptException('The payload is invalid.');
        }
        $payload = base64_decode($payload);
        if ($payload === false || !str_contains($payload, '|')) {
            throw new DecryptException('The payload is invalid.');
        }
        [$payload, $hash] = explode('|', $payload, 2);
        if (!hash_equals(hash('sha512', $payload), $hash)) {
            throw new DecryptException('The payload is invalid.');
        }
        try {
            $payload = json_decode(base64_decode($payload), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new DecryptException('The payload is invalid: ' . $e->getMessage());
        }
        if (! $this->validPayload($payload)) {
            throw new DecryptException('The payload is invalid.');
        }
        return $payload;
    }

    /**
     * Verify that the encryption payload is valid.
     */
    protected function validPayload(array $payload): bool
    {
        foreach (['iv', 'value', 'mac'] as $item) {
            if (! isset($payload[$item]) || ! is_string($payload[$item])) {
                return false;
            }
        }

        if (isset($payload['tag']) && ! is_string($payload['tag'])) {
            return false;
        }

        return strlen(base64_decode($payload['iv'], true)) === openssl_cipher_iv_length(strtolower($this->cipher));
    }

    /**
     * Determine if the MAC for the given payload is valid for the primary key.
     */
    protected function validMac(array $payload): bool
    {
        return $this->validMacForKey($payload, $this->key);
    }

    /**
     * Determine if the MAC is valid for the given payload and key.
     */
    protected function validMacForKey(#[SensitiveParameter] array $payload, string $key): bool
    {
        return hash_equals($this->hash($payload['iv'], $payload['value'], $key), $payload['mac']);
    }

    /**
     * Ensure the given tag is a valid tag given the selected cipher.
     *
     * @throws DecryptException
     */
    protected function ensureTagIsValid(mixed $tag): void
    {
        if ($this->aead && strlen($tag) !== 16) {
            throw new DecryptException('Could not decrypt the data.');
        }

        if (!$this->aead && is_string($tag)) {
            throw new DecryptException('Unable to use tag because the cipher algorithm does not support AEAD.');
        }
    }

    /**
     * Determine if we should validate the MAC while decrypting.
     */
    protected function shouldValidateMac(): bool
    {
        return !$this->aead;
    }

    /**
     * Get the encryption key that the encrypter is currently using.
     */
    public function getKey(): string
    {
        return $this->key;
    }
}
