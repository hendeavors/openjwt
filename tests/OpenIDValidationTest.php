<?php

namespace Endeavors\OpenJWT\Tests;

use PHPUnit\Framework\TestCase;
use Endeavors\OpenJWT\OpenIDToken;
use Endeavors\OpenJWT\Validator\AudienceValidator;
use Firebase\JWT\JWT;

class OpenIDValidationTest extends TestCase
{
    /**
     * @test
     */
    public function singleAudience()
    {
        $key = "example_key";
        $token = array(
            "sub" => "portal",
            "iss" => "http://example.org",
            "aud" => "http://example.com",
            "iat" => 1356999524,
            "nbf" => 1357000000
        );

        $jwt = JWT::encode($token, $key);

        $token = OpenIDToken::create($jwt)
        ->requestedAt(time())
        ->client("http://example.com")
        ->provider("http://example.org")
        ->decode();

        $this->assertEquals("portal", $token->sub);
    }

    /**
     * @test
     */
    public function multipleAudience()
    {
        $key = "example_key";
        $token = array(
            "sub" => "portal",
            "iss" => "http://example.org",
            "aud" => ["http://example.com", "http://google.com"],
            "azp" => ["http://example.com", "http://google.com"],
            "iat" => 1356999524,
            "nbf" => 1357000000
        );

        $jwt = JWT::encode($token, $key);

        $token = OpenIDToken::create($jwt)
        ->client("http://example.com", "http://google.com")
        ->requestedAt(time())
        ->provider("http://example.org")
        ->decode();

        $this->assertEquals("portal", $token->sub);
    }

    /**
     * @test
     */
    public function signed()
    {
        $privateKey = <<<EOD
        -----BEGIN RSA PRIVATE KEY-----
        MIICXAIBAAKBgQC8kGa1pSjbSYZVebtTRBLxBz5H4i2p/llLCrEeQhta5kaQu/Rn
        vuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t0tyazyZ8JXw+KgXTxldMPEL9
        5+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4ehde/zUxo6UvS7UrBQIDAQAB
        AoGAb/MXV46XxCFRxNuB8LyAtmLDgi/xRnTAlMHjSACddwkyKem8//8eZtw9fzxz
        bWZ/1/doQOuHBGYZU8aDzzj59FZ78dyzNFoF91hbvZKkg+6wGyd/LrGVEB+Xre0J
        Nil0GReM2AHDNZUYRv+HYJPIOrB0CRczLQsgFJ8K6aAD6F0CQQDzbpjYdx10qgK1
        cP59UHiHjPZYC0loEsk7s+hUmT3QHerAQJMZWC11Qrn2N+ybwwNblDKv+s5qgMQ5
        5tNoQ9IfAkEAxkyffU6ythpg/H0Ixe1I2rd0GbF05biIzO/i77Det3n4YsJVlDck
        ZkcvY3SK2iRIL4c9yY6hlIhs+K9wXTtGWwJBAO9Dskl48mO7woPR9uD22jDpNSwe
        k90OMepTjzSvlhjbfuPN1IdhqvSJTDychRwn1kIJ7LQZgQ8fVz9OCFZ/6qMCQGOb
        qaGwHmUK6xzpUbbacnYrIM6nLSkXgOAwv7XXCojvY614ILTK3iXiLBOxPu5Eu13k
        eUz9sHyD6vkgZzjtxXECQAkp4Xerf5TGfQXGXhxIX52yH+N2LtujCdkQZjXAsGdm
        B2zNzvrlgRmgBrklMTrMYgm1NPcW+bRLGcwgW2PTvNM=
        -----END RSA PRIVATE KEY-----
EOD;

        $publicKey = <<<EOD
        -----BEGIN PUBLIC KEY-----
        MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8kGa1pSjbSYZVebtTRBLxBz5H
        4i2p/llLCrEeQhta5kaQu/RnvuER4W8oDH3+3iuIYW4VQAzyqFpwuzjkDI+17t5t
        0tyazyZ8JXw+KgXTxldMPEL95+qVhgXvwtihXC1c5oGbRlEDvDF6Sa53rcFVsYJ4
        ehde/zUxo6UvS7UrBQIDAQAB
        -----END PUBLIC KEY-----
EOD;

        $token = array(
            "sub" => "portal",
            "iss" => "http://example.org",
            "aud" => ["http://example.com", "http://google.com"],
            "azp" => ["http://example.com", "http://google.com"],
            "iat" => 1356999524,
            "nbf" => 1357000000
        );

        $privateKey = \Endeavors\OpenJWT\Support\trim($privateKey);
        $publicKey = \Endeavors\OpenJWT\Support\trim($publicKey);

        $jwt = JWT::encode($token, $privateKey, 'RS256');

        $token = OpenIDToken::create($jwt)
        ->client("http://example.com", "http://google.com")
        ->signed($publicKey)
        ->requestedAt(time())
        ->provider("http://example.org")
        ->decode();

        $this->assertEquals("portal", $token->sub);
    }
}
