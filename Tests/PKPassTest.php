<?php

namespace PKPass\Tests;

use PKPass\PKPass;

/**
 * Class Test
 * @package PKPass\Tests
 */
class PKPassTest extends \PHPUnit_Framework_TestCase
{

    public function testPKPassInit()
    {
        $pass = new PKPass();
        $this->assertEquals('', $pass->getCertificate());


        $pass = new PKPass(__FILE__, 'password', json_encode([]));
        $this->assertEquals(__FILE__, $pass->getCertificate());
        $this->assertNotEquals('/missing/path', $pass->getCertificate());

        $pass = new PKPass(__FILE__, 'password');
        $this->assertEquals('password', $pass->getCertificatePassword());

        $pass = new PKPass(__FILE__);
        $this->assertEquals('', $pass->getCertificatePassword());
    }

    public function testSettingCertificates()
    {
        $pass = $this->getPKPass();
        $pass->setCertificate(__FILE__);

        $this->setExpectedException('\PkPass\Exception\CertificateException');
        $pass->setCertificate('/missing/path');
    }

    /**
     *
     */
    public function testSettingWwdrCertificatePath()
    {
        $pass = $this->getPKPass();
        $pass->setWwdrCertificatePath(__FILE__);
    }

    public function testName()
    {
        $pass = $this->getPKPass();
        $pass->setName('PKPass');

        $this->assertEquals('PKPass', $pass->getName());
    }

    /**
     *
     */
    public function testSettingCertificatePassword()
    {
        $pass = $this->getPKPass();
        $pass->setCertificatePassword('password');

        $this->assertEquals('password', $pass->getCertificatePassword());
    }

    /**
     * @expectedException \PKPass\Exception\JsonException
     */
    public function testInvalidJson()
    {
        $pass = $this->getPKPass();

        $pass->setJson('hello');
    }

    public function testValidJson()
    {
        $pass = $this->getPKPass();
        $pass->setJson(json_encode(['Test']));
    }

    public function testSettingTemporaryPath()
    {
        $pass = $this->getPKPass();
        $pass->setTemporaryPath('/tmp/');

        $this->setExpectedException('\PkPass\Exception\CertificateException');
        $pass->setTemporaryPath('/missing/path');
    }

    public function testAddingFiles()
    {
        $pass = $this->getPKPass();

        $pass->addFile(__DIR__ . '/Resources/icon.png');
        $pass->addFile(__DIR__ . '/Resources/icon@2x.png', 'icon-bigger.png');

        $files = $pass->getFiles();

        $this->assertArrayHasKey('icon.png', $files);
        $this->assertArrayHasKey('icon-bigger.png', $files);

        $this->assertArrayNotHasKey('icon@2x.png', $files);

        $this->setExpectedException('\PkPass\Exception\CertificateException');
        $pass->addFile(__DIR__ . '/Resources/background.png');
    }

    public function testCreatingPassbookWithMissingIcon()
    {
        $pass = $this->getPKPass(__DIR__ . '/Resources/Certificates/AppleWWDRCA.pem', 'password');
        $pass->setWwdrCertificatePath(__DIR__ . '/Resources/Certificates/AppleWWDRCA.pem');

        $this->setExpectedException('\PkPass\Exception\CertificateException', 'Missing required icon.png file');
        $pass->create();
    }

    public function testCreatingPassbookWithInvalidCertificate()
    {
        $pass = $this->getPKPass(__DIR__ . '/Resources/Certificates/AppleWWDRCA.pem', 'password');
        $pass->setWwdrCertificatePath(__DIR__ . '/Resources/Certificates/AppleWWDRCA.pem');

        $pass->addFile(__DIR__ . '/Resources/icon.png');

        $this->setExpectedException('\PkPass\Exception\CertificateException', 'Could not read the certificate');

        $pass->create();
    }

    public function testCreatingPassbookWithInvalidCertificatePassword()
    {
        $pass = $this->getPKPass(__DIR__ . '/Resources/Certificates/PKPassTest.p12', 'password1');
        $pass->setWwdrCertificatePath(__DIR__ . '/Resources/Certificates/AppleWWDRCA.pem');

        $pass->addFile(__DIR__ . '/Resources/icon.png');

        $this->setExpectedException('\PkPass\Exception\CertificateException', 'Could not read the certificate');
        $pass->create();
    }

    public function testCreatingPassbookWithValidCertificates()
    {
        $pass = $this->getPKPass(__DIR__ . '/Resources/Certificates/PKPassTest.p12', 'password');
        $pass->setWwdrCertificatePath(__DIR__ . '/Resources/Certificates/AppleWWDRCA.pem');

        $pass->addFile(__DIR__ . '/Resources/icon.png');

        $file = $pass->create();

        $this->assertNotEmpty($file);
    }


    public function testCreatingPassbookWithInvalidWwdrCertificate()
    {
        $pass = $this->getPKPass(__DIR__ . '/Resources/Certificates/PKPassTest.p12', 'password');
        $pass->setWwdrCertificatePath(__DIR__ . '/Resources/Certificates/AppleWWDRCA-not-here.pem');

        $pass->addFile(__DIR__ . '/Resources/icon.png');

        $this->setExpectedException('\PkPass\Exception\CertificateException', 'WWDR Intermediate Certificate does not exist');
        $pass->create();
    }

    public function testSettingTemporaryPathWithMissingTrailingSlash()
    {
        $pass = $this->getPKPass(__DIR__ . '/Resources/Certificates/PKPassTest.p12', 'password');
        $pass->setWwdrCertificatePath(__DIR__ . '/Resources/Certificates/AppleWWDRCA.pem');
        $pass->setTemporaryPath('/tmp');

        $pass->addFile(__DIR__ . '/Resources/icon.png');

        $pass->create();
    }

    /**
     * @param string|null $certificatePath
     * @param string|null $password
     *
     * @return \PKPass\PKPass
     */
    private function getPKPass($certificatePath = null, $password = null)
    {
        return new PKPass($certificatePath, $password);
    }
}
