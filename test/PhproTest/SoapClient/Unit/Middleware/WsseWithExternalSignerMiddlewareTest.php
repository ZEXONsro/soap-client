<?php

namespace PhproTest\SoapClient\Unit\Middleware;

use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Http\Client\Common\PluginClient;
use Http\Message\MessageFactory\GuzzleMessageFactory;
use Http\Mock\Client;
use Phpro\SoapClient\Middleware\WsseMiddleware;
use Phpro\SoapClient\Middleware\MiddlewareInterface;
use Phpro\SoapClient\Middleware\WsseWithExternalSignerMiddleware;
use Phpro\SoapClient\Xml\SoapXml;
use PHPUnit\Framework\TestCase;
use RobRichards\WsePhp\WSSEExternalXmlSignerInterface;
use RobRichards\WsePhp\WSSEExternalXmlSignerResponseDTO;

/**
 * Class WsseWithExternalSignerMiddleware
 *
 * @group Middleware
 * @package PhproTest\SoapClient\Unit\Middleware
 */
class WsseWithExternalSignerMiddlewareTest extends TestCase
{
    /**
     * @var PluginClient
     */
    private $client;

    /**
     * @var Client
     */
    private $mockClient;

    /**
     * @var WsseMiddleware
     */
    private $middleware;

    /**
     * @var WSSEExternalXmlSignerInterface
     */
    private $externalSignerMock;

    /**
     * @var WSSEExternalXmlSignerInterface
     */
    private $failingExternalSignerMock;

    /***
     * Initialize all basic objects
     */
    protected function setUp()
    {
        $soapSignedRequest = file_get_contents(FIXTURE_DIR . '/soap/basic-pz-signed-response.xml');
        $signerResponseObject = new WSSEExternalXmlSignerResponseDTO($soapSignedRequest,null,null,null,false);
        $this->middleware = new WsseWithExternalSignerMiddleware();
        $this->externalSignerMock = $this->getMockBuilder('RobRichards\WsePhp\WSSEExternalXmlSignerInterface')->getMock();
        $this->externalSignerMock->expects($this->any())->method('signXml')->will($this->returnValue($signerResponseObject));
        $this->failingExternalSignerMock = $this->getMockBuilder('RobRichards\WsePhp\WSSEExternalXmlSignerInterface')->getMock();
        $this->failingExternalSignerMock
            ->expects($this->any())
            ->method('signXml')
            ->will($this->returnValue(new WSSEExternalXmlSignerResponseDTO(null,'TestException','Signer failed for testing purposes',null,true)));
        $this->middleware->withExternalSigner($this->externalSignerMock,['PreskripcnyZaznam']);
        $this->mockClient = new Client(new GuzzleMessageFactory());
        $this->client = new PluginClient($this->mockClient, [$this->middleware]);
    }

    /**
     * @test
     */
    function it_is_a_middleware()
    {
        $this->assertInstanceOf(MiddlewareInterface::class, $this->middleware);
    }

    /**
     * @test
     */
    function it_has_a_name()
    {
        $this->assertEquals('wsse_with_external_signer_middleware', $this->middleware->getName());
    }

    /**
     * @test
     */
    public function it_has_a_correct_signer()
    {
        $soapSignedRequest = file_get_contents(FIXTURE_DIR . '/soap/basic-pz-signed-response.xml');
        $this->assertEquals($soapSignedRequest,$this->externalSignerMock->signXml('some xml')->getSignedXml());
        $this->assertInstanceOf(WSSEExternalXmlSignerInterface::class,$this->externalSignerMock);
        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/basic-pz-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $result = $this->client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xml = $this->fetchSoapXml($soapBody);
    }

    /**
     * @test
     */
    function it_adds_Wsse_to_the_request_xml()
    {
        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/basic-pz-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $result = $this->client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xml = $this->fetchSoapXml($soapBody);

        $this->assertEquals($result, $response);

        // Check request structure:
        $this->assertEquals($xml->xpath('//soap:Header/wsse:Security')->length, 1, 'No WSSE Security tag');

        $this->assertEquals($xml->xpath('//ds:Signature')->length, 1, 'No DS Signature tag');
        $this->assertEquals($xml->xpath('//ds:Signature/ds:SignedInfo')->length, 1, 'No DS SignedInfo Signature tag');
        $this->assertEquals($xml->xpath('//ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod')->length, 1, 'No DS SignedInfo CanonicalizationMethod Signature tag');
        $this->assertEquals($xml->xpath('//ds:Signature/ds:SignedInfo/ds:SignatureMethod')->length, 1, 'No DS SignedInfo SignatureMethod Signature tag');
        $this->assertEquals($xml->xpath('//ds:Signature/ds:SignedInfo/ds:Reference')->length, 1, 'No DS SignedInfo Reference Signature tag'.$xml->toString());
        $this->assertEquals($xml->xpath('//ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform')->length, 1, 'No DS SignedInfo Reference Transform Signature tag');
        $this->assertEquals($xml->xpath('//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod')->length, 1, 'No DS SignedInfo Reference DigestMethod Signature tag');
        $this->assertEquals($xml->xpath('//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue')->length, 1, 'No DS SignedInfo Reference DigestValue Signature tag');
        $this->assertEquals($xml->xpath('//ds:Signature/ds:SignatureValue')->length, 1, 'No DS SignatureValue Signature tag');
        $this->assertEquals($xml->xpath('//ds:Signature/ds:KeyInfo')->length, 1, 'No DS KeyInfo Signature tag');
        //$this->assertEquals($xml->xpath('//ds:Signature/ds:KeyInfo/wsse:SecurityTokenReference/wsse:Reference')->length, 1, 'No DS KeyInfo SecurityTokenReference Signature tag');

        $this->assertEquals($xml->xpath('//wsse:Security/wsu:Timestamp')->length, 1, 'No WSU Timestamp tag');
        $this->assertEquals($xml->xpath('//wsse:Security/wsu:Timestamp/wsu:Created')->length, 1, 'No WSU Created Timestamp tag');
        $this->assertEquals($xml->xpath('//wsse:Security/wsu:Timestamp/wsu:Expires')->length, 1, 'No WSU Expires Timestamp tag');


        // Check defaults:
        /*
         * We doesn't test it since we doesn't know anything about external signer params
        $this->assertEquals(
            XMLSecurityKey::RSA_SHA1,
            (string) $xml->xpath('//ds:SignatureMethod')->item(0)->getAttribute('Algorithm')
        );
        */
        $this->assertEquals(
            strtotime((string) $xml->xpath('//wsu:Created')->item(0)->nodeValue),
            strtotime((string) $xml->xpath('//wsu:Expires')->item(0)->nodeValue) - 3600
        );
    }

    /**
     * @test
     * @expectedException \Exception
     * @expectedExceptionMessageRegExp  ".*Signer failed for testing purposes.*"
     */
    function it_will_fail_on_signer_fail()
    {
        $this->middleware->withExternalSigner($this->failingExternalSignerMock,['PreskripcnyZaznam']);
        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/basic-pz-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $result = $this->client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xml = $this->fetchSoapXml($soapBody);
    }

    /**
     * @test
     */
    function it_is_possible_to_configure_expiry_ttl()
    {
        $this->middleware->withTimestamp(100);
        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $this->client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xml = $this->fetchSoapXml($soapBody);

        $this->assertEquals(
            strtotime((string) $xml->xpath('//wsu:Created')->item(0)->nodeValue),
            strtotime((string) $xml->xpath('//wsu:Expires')->item(0)->nodeValue) - 100
        );
    }

     /**
     * @test
     */
    function it_is_possible_to_specify_a_user_token()
    {
        $this->middleware->withUserToken('username', 'password', false);
        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $this->client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xml = $this->fetchSoapXml($soapBody);

        // Check defaults:
        $this->assertEquals($xml->xpath('//soap:Header/wsse:Security/wsse:UsernameToken')->length, 1, 'No WSSE UsernameToken tag');
        $this->assertEquals($xml->xpath('//wsse:Security/wsse:UsernameToken/wsse:Username')->length, 1, 'No WSSE UserName tag');
        $this->assertEquals($xml->xpath('//wsse:Security/wsse:UsernameToken/wsse:Password')->length, 1, 'No WSSE Password tag');
        $this->assertEquals($xml->xpath('//wsse:Security/wsse:UsernameToken/wsse:Nonce')->length, 1, 'No WSSE Nonce tag');
        $this->assertEquals($xml->xpath('//wsse:Security/wsse:UsernameToken/wsu:Created')->length, 1, 'No WSU Created tag');

        // Check values:
        $this->assertEquals('username', (string) $xml->xpath('//wsse:Username')->item(0)->nodeValue);
        $this->assertEquals('password', (string) $xml->xpath('//wsse:Password')->item(0)->nodeValue);
        $this->assertEquals(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText',
            (string) $xml->xpath('//wsse:Password')->item(0)->getAttribute('Type')
        );
    }

    /**
     * @test
     */
    function it_is_possible_to_specify_a_user_token_with_digest()
    {
        $this->middleware->withUserToken('username', 'password', true);
        $soapRequest = file_get_contents(FIXTURE_DIR . '/soap/empty-request.xml');
        $this->mockClient->addResponse($response = new Response(200));
        $this->client->sendRequest($request = new Request('POST', '/', ['SOAPAction' => 'myaction'], $soapRequest));

        $soapBody = (string)$this->mockClient->getRequests()[0]->getBody();
        $xml = $this->fetchSoapXml($soapBody);

        // Check defaults:
        $this->assertEquals($xml->xpath('//soap:Header/wsse:Security/wsse:UsernameToken')->length, 1, 'No WSSE UsernameToken tag');
        $this->assertEquals($xml->xpath('//wsse:Security/wsse:UsernameToken/wsse:Username')->length, 1, 'No WSSE UserName tag');
        $this->assertEquals($xml->xpath('//wsse:Security/wsse:UsernameToken/wsse:Password')->length, 1, 'No WSSE Password tag');
        $this->assertEquals($xml->xpath('//wsse:Security/wsse:UsernameToken/wsse:Nonce')->length, 1, 'No WSSE Nonce tag');
        $this->assertEquals($xml->xpath('//wsse:Security/wsse:UsernameToken/wsu:Created')->length, 1, 'No WSU Created tag');

        // Check values:
        $this->assertEquals('username', (string) $xml->xpath('//wsse:Username')->item(0)->nodeValue);
        $this->assertNotEquals('password', (string) $xml->xpath('//wsse:Password')->item(0)->nodeValue);
        $this->assertEquals(
            'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest',
            (string) $xml->xpath('//wsse:Password')->item(0)->getAttribute('Type')
        );
    }

    /**
     * @param $soapBody
     *
     * @return SoapXml
     */
    private function fetchSoapXml($soapBody): SoapXml
    {
        $xml = new \DOMDocument();
        $xml->loadXML($soapBody);

        $soapXml = new SoapXml($xml);
        $soapXml->registerNamespace('wsse', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd');
        $soapXml->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
        $soapXml->registerNamespace('wsu', 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd');
        $soapXml->registerNamespace('wsa', 'http://schemas.xmlsoap.org/ws/2004/08/addressing');
        $soapXml->registerNamespace('xenc', 'http://www.w3.org/2001/04/xmlenc#');
        $soapXml->registerNamespace('dsig', 'http://www.w3.org/2000/09/xmldsig#');

        return $soapXml;
    }
}
