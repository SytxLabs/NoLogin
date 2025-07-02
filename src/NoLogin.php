<?php

namespace SytxLabs\NoLogin;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\RequestOptions;
use InvalidArgumentException;
use JsonException;
use SensitiveParameter;
use SytxLabs\NoLogin\Encrypt\Encrypter;
use SytxLabs\NoLogin\Encrypt\SupportedCiphers;

class NoLogin
{
    /** @var array{scopes: array<string>, oAuthPath: string, oAuthPath: string, oAuthApiMethod: string, oAuthApiTimeout: int} */
    private array $options;

    private Encrypter $encrypter;

    public function __construct(private string $url, private readonly string $clientId, #[SensitiveParameter] private string $clientSecret, array $options = [])
    {
        if (empty($this->url) || empty($this->clientId) || empty($this->clientSecret)) {
            throw new InvalidArgumentException('NoLogin URL, Client ID, and Client Secret must be provided.');
        }
        $cSecret = base64_decode($clientSecret, true);
        if ($cSecret !== false) {
            $clientSecret = $cSecret;
        }
        $this->clientSecret = $clientSecret;
        $this->url = str_starts_with($this->url, 'http') ? $this->url : 'https://'.$this->url;
        if (str_ends_with($this->url, '/')) {
            $this->url = rtrim($this->url, '/');
        }
        $this->options = array_replace([
            'scopes' => Scope::defaultScopes(),
            'oAuthPath' => '/nologin/oauth',
            'oAuthApiPath' => '/api/nologin/auth',
            'oAuthApiMethod' => 'POST',
            'oAuthApiTimeout' => 20,
        ], $options);
        $this->encrypter = new Encrypter($this->clientSecret, SupportedCiphers::AES_256_CBC);
    }

    public function getUrl(): string
    {
        return $this->url;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function setOptions(array $options): self
    {
        $this->options = array_replace($this->options, $options);
        return $this;
    }

    public function getOptions(): array
    {
        return $this->options;
    }

    public function generateLoginUrl(?string $redirectUrl = null): string
    {
        $redirectUrl = $redirectUrl ?? $this->options['redirectUrl'] ?? null;
        if (empty($redirectUrl)) {
            throw new InvalidArgumentException('Redirect URL must be provided.');
        }
        $query = http_build_query([
            'client_id' => $this->clientId,
            'redirect_uri' => $redirectUrl,
            'response_type' => 'code',
            'scope' => implode(',', $this->options['scopes']),
        ]);
        $oAuthPath = $this->options['oAuthPath'] ?? '/nologin/oauth';
        if (!str_starts_with($oAuthPath, '/')) {
            $oAuthPath = '/' . $oAuthPath;
        }
        if (str_ends_with($oAuthPath, '/')) {
            $oAuthPath = rtrim($oAuthPath, '/');
        }
        return $this->url . $oAuthPath . '?' . $query;
    }

    /**
     * Handles the NoLogin request and returns a NoLoginApiResponse.
     *
     * @param string $code The encrypted code received from the NoLogin OAuth flow.
     * @throws InvalidArgumentException If the code is invalid or the request fails.
     */
    public function handleRequest(#[SensitiveParameter] string $code): NoLoginApiResponse
    {
        try {
            $code = $this->encrypter->decrypt($code);
        } catch (Encrypt\DecryptException $e) {
            throw new InvalidArgumentException('Invalid code provided for NoLogin request.', 0, $e);
        }
        $parts = explode('|', $code, 5);
        if (count($parts) !== 5) {
            throw new InvalidArgumentException('Invalid code format provided for NoLogin request.');
        }
        [$clientId, $userId, $token, $time, $hash] = $parts;
        if ($clientId !== $this->clientId) {
            throw new InvalidArgumentException('Client ID does not match the configured NoLogin client ID.');
        }
        $now = time();
        // Validate the time the token is only valid for 5 minutes
        if ($now - (int) $time > 300) {
            throw new InvalidArgumentException('Token has expired.');
        }
        // Validate the hash
        $expectedHash = hash_hmac('sha256', $clientId . '|' . $userId . '|' . $token . '|' . $time, $this->clientSecret);
        if (!hash_equals($expectedHash, $hash)) {
            throw new InvalidArgumentException('Invalid token hash.');
        }
        // send user request to NoLogin API
        $apiPath = $this->options['oAuthApiPath'] ?? '/api/nologin/auth';
        if (!str_starts_with($apiPath, '/')) {
            $apiPath = '/' . $apiPath;
        }
        if (str_ends_with($apiPath, '/')) {
            $apiPath = rtrim($apiPath, '/');
        }
        $url = $this->url . $apiPath;
        $content = [
            'user_id' => $userId,
            'time' => $now,
        ];
        $client = new Client([
            RequestOptions::HEADERS => [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'hash' => hash_hmac('sha256', $clientId . '|' . $userId . '|' . $token . '|' . $now, $this->clientSecret),
            ],
            RequestOptions::TIMEOUT => $this->options['oAuthApiTimeout'] ?? 20,
            RequestOptions::AUTH => [
                $this->clientId,
                $token,
            ],
        ]);
        try {
            $response = $client->request($this->options['oAuthApiMethod'], $url, [
                'json' => $content,
            ]);
        } catch (GuzzleException $e) {
            throw new InvalidArgumentException('NoLogin API request failed: ' . $e->getMessage(), 0, $e);
        }
        if ($response->getStatusCode() !== 200) {
            throw new InvalidArgumentException('NoLogin API request failed with status code: ' . $response->getStatusCode());
        }
        try {
            $result = json_decode($response->getBody()->getContents(), true, 512, JSON_THROW_ON_ERROR);
            if (!isset($result['success']) || !$result['success']) {
                throw new InvalidArgumentException('NoLogin API request failed with error: ' . ($result['error'] ?? 'Unknown error'));
            }
        } catch (JsonException) {
            throw new InvalidArgumentException('NoLogin API request failed with invalid JSON response.');
        }
        try {
            $decryptedContent = $this->encrypter->decrypt($result['content'] ?? '');
            $content = json_decode($decryptedContent, true, 512, JSON_THROW_ON_ERROR);
            if ($result['hash'] !== hash_hmac('sha512', $result['content'], $this->clientSecret)) {
                throw new InvalidArgumentException('NoLogin API response hash does not match.');
            }
            return new NoLoginApiResponse(
                $content['email'] ?? null,
                $content['username'] ?? null,
                $content['avatar'] ?? null,
                $content['salutation'] ?? null,
                $content['title'] ?? null,
                $content['language'] ?? null,
            );
        } catch (Encrypt\DecryptException|JsonException $e) {
            throw new InvalidArgumentException('NoLogin API request failed with invalid content.', 0, $e);
        }
    }
}
