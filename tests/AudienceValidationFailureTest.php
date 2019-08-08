<?php

namespace Endeavors\OpenJWT\Tests;

use PHPUnit\Framework\TestCase;
use Endeavors\OpenJWT\Inspect;
use Endeavors\OpenJWT\Validator\AudienceValidator;
use Firebase\JWT\JWT;

class AudienceValidationFailureTest extends TestCase
{
    /**
     * @test
     * @expectedException \UnexpectedValueException
     * @expectedExceptionMessage  An authorized party claim must be present
     */
    public function authorizedPartyClaimMustBePresent()
    {
        $key = "example_key";
        $token = array(
            "sub" => "portal",
            "iss" => "http://example.org",
            "aud" => ["http://example.com", "http://google.com"],
            "iat" => 1356999524,
            "nbf" => 1357000000
        );

        $jwt = JWT::encode($token, $key);

        $this->assertEquals("portal", Inspect::audience($jwt, "http://example.com", "http://google.com")->sub);
    }

    /**
     * @test
     * @expectedException \UnexpectedValueException
     * @expectedExceptionMessage  The authorized party received does not match the given set of audiences
     */
    public function invalidAuthorizedPartyClaimPresent()
    {
        $key = "example_key";
        $token = array(
            "sub" => "portal",
            "iss" => "http://example.org",
            "aud" => ["http://example.com", "http://google.com"],
            "azp" => "foo",
            "iat" => 1356999524,
            "nbf" => 1357000000
        );

        $jwt = JWT::encode($token, $key);

        $this->assertEquals("portal", Inspect::audience($jwt, "http://example.com", "http://google.com")->sub);
    }

    /**
     * @test
     * @expectedException \UnexpectedValueException
     * @expectedExceptionMessage The authorized party claim is not valid.
     */
    public function nullAuthorizedPartyClaimPresent()
    {
        $key = "example_key";
        $token = array(
            "sub" => "portal",
            "iss" => "http://example.org",
            "aud" => ["http://example.com", "http://google.com"],
            "azp" => null,
            "iat" => 1356999524,
            "nbf" => 1357000000
        );

        $jwt = JWT::encode($token, $key);

        $this->assertEquals("portal", Inspect::audience($jwt, "http://example.com", "http://google.com")->sub);
    }

    /**
     * @test
     * @expectedException \UnexpectedValueException
     * @expectedExceptionMessage  Wrong number of segments
     */
    public function wrongNumberOfSegments()
    {
        $token = "test";

        Inspect::audience($token, "foo");
    }

    /**
     * @test
     * @expectedException \UnexpectedValueException
     */
    public function validationWrongNumberOfSegments()
    {
        $validator = new AudienceValidator("test", "bar");

        $validator->validate();
    }
}
