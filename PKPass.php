<?php
/**
 * PKPass - Creates iOS 6 passes
 *
 * Author: Tom Schoffelen
 * Revision: Tom Janssen
 *
 * www.tomttb.com
 */

namespace PKPass;

use PKPass\Exception\CertificateException;
use PKPass\Exception\JsonException;
use PKPass\Exception\PKPassException;
use PKPass\Exception\ZipException;
use ZipArchive as ZipArchive;

/**
 * Class PKPass
 * @package PKPass
 */
class PKPass
{
    /**
     * Holds the path to the certificate
     * Variable: string
     */
    protected $certificatePath;

    /**
     * Name of the downloaded file.
     */
    protected $name;

    /**
     * Holds the files to include in the .pkpass
     * Variable: array
     */
    protected $files = [];

    /**
     * Holds the json
     * Variable: class
     */
    protected $json;

    /**
     * Holds the SHAs of the $files array
     * Variable: array
     */
    protected $SHAs;

    /**
     * Holds the password to the certificate
     * Variable: string
     */
    protected $certificatePass = '';

    /**
     * Holds the path to the WWDR Intermediate certificate
     * Variable: string
     */
    protected $wwdrCertificatePath = '';

    /**
     * Holds the path to a temporary folder
     */
    protected $tempPath = '/tmp/'; // Must end with slash!

    /**
     * Holds an auto generated unique ID to prevent overwriting other processes pass files
     */
    private $uniqid = null;

    /**
     * PKPass constructor.
     *
     * @param bool $certificatePath
     * @param bool $certificatePassword
     * @param bool $json
     */
    public function __construct($certificatePath = null, $certificatePassword = null, $json = null)
    {
        if (!empty($certificatePath)) {
            $this->setCertificate($certificatePath);
        }

        if (!empty($certificatePassword)) {
            $this->setCertificatePassword($certificatePassword);
        }

        if (!empty($json)) {
            $this->setJson($json);
        }
    }

    /**
     * Sets the path to a certificate
     * Parameter: string, path to certificate
     * Return: boolean, true on succes, false if file doesn't exist
     *
     * @param $path
     *
     * @return self
     */
    public function setCertificate($path)
    {
        if (!file_exists($path)) {
            throw new CertificateException('Certificate file does not exist');
        }

        $this->certificatePath = $path;

        return $this;
    }


    public function getCertificate()
    {
        return $this->certificatePath;
    }

    /**
     * Sets the certificate's password
     *
     * @param string $password Password to the certificate
     *
     * @return self
     */
    public function setCertificatePassword($password)
    {
        $this->certificatePass = $password;

        return $this;
    }


    /**
     * @return string
     */
    public function getCertificatePassword()
    {
        return $this->certificatePass;
    }

    /**
     * Sets the path to the WWDR Intermediate certificate
     * Parameter: string, path to certificate
     * Return: boolean, always true
     *
     * @param $path
     *
     * @return self
     */
    public function setWwdrCertificatePath($path)
    {
        $this->wwdrCertificatePath = $path;

        return $this;
    }

    /**
     * Sets the path to the temporary directory (must end with a slash)
     * Parameter: string, path to temporary directory
     * Return: boolean, true on success, false if directory doesn't exist
     *
     * @param $path
     *
     * @return bool
     */
    public function setTemporaryPath($path)
    {
        if (!is_dir($path)) {
            throw new CertificateException('Temporary path not found');
        }

        $this->tempPath = $path;

        return $this;
    }

    /**
     * Decodes JSON and saves it to a variable
     * Parameter: json-string
     * Return: boolean, true on success, false if json wasn't decodable
     *
     * @param $json
     *
     * @return bool
     */
    public function setJson($json)
    {
        if (json_decode($json) === null) {
            throw new JsonException('This is not a JSON string');
        }
        $this->json = $json;

        return $this;
    }

    /**
     * Adds file to the file array
     *
     * @param string      $path path to file
     * @param null|string $name Optional name to create the file as
     *
     * @throws CertificateException
     *
     * @return self
     */
    public function addFile($path, $name = null)
    {
        if (!file_exists($path)) {
            throw new CertificateException('File does not exist');
        }

        $this->files[$name ?: basename($path)] = $path;

        return $this;
    }

    /**
     * @return array
     */
    public function getFiles()
    {
        return $this->files;
    }

    /**
     * Creates the actual .pkpass file
     *
     * @param bool $output if output is true, send the zip file to the browser
     *
     * @throws PKPassException
     *
     * @return string Zipped .pkpass file on success
     */
    public function create($output = false)
    {
        $paths = $this->paths();

        //Creates and saves the json manifest
        $manifest = $this->createManifest();

        $this->createSignature($manifest);
        $this->createZip($manifest);

        // Output pass
        if ($output == true) {

            $fileName = $this->getName() ?: basename($paths['pkpass']);
            header('Pragma: no-cache');
            header('Content-type: application/vnd.apple.pkpass');
            header('Content-length: ' . filesize($paths['pkpass']));
            header('Content-Disposition: attachment; filename="' . $fileName . '"');
        }

        $file = file_get_contents($paths['pkpass']);
        $this->clean();

        return $file;
    }

    /**
     * @return mixed
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * @param $name
     */
    public function setName($name)
    {
        $this->name = $name;
    }

    /**
     * This function creates the hashes for the files and adds them into a json string.
     *
     * @throws CertificateException
     *
     * @return string
     */
    protected function createManifest()
    {
        // Creates SHA hashes for all files in package
        $this->SHAs['pass.json'] = sha1($this->json);

        if (!isset($this->files['icon.png'])) {
            throw new CertificateException('Missing required icon.png file');
        }

        foreach ($this->getFiles() as $name => $path) {
            $this->SHAs[$name] = sha1(file_get_contents($path));
        }

        $manifest = json_encode($this->SHAs, JSON_FORCE_OBJECT);

        return $manifest;
    }

    /**
     * Converts PKCS7 PEM to PKCS7 DER
     *
     * @param string $signature holding PKCS7 PEM, binary, detached
     *
     * @return string PKCS7 DER
     */
    protected function convertPEMtoDER($signature)
    {
        $begin     = 'filename="smime.p7s"';
        $end       = '------';
        $signature = substr($signature, strpos($signature, $begin) + strlen($begin));

        $signature = substr($signature, 0, strpos($signature, $end));
        $signature = trim($signature);
        $signature = base64_decode($signature);

        return $signature;
    }

    /**
     * Creates a signature and saves it
     *
     * @param string $manifest json-string, manifest file
     *
     * @throws CertificateException
     *
     * @return bool
     */
    protected function createSignature($manifest)
    {
        $paths = $this->paths();

        file_put_contents($paths['manifest'], $manifest);

        $pkcs12 = file_get_contents($this->certificatePath);
        $certs  = [];

        if (openssl_pkcs12_read($pkcs12, $certs, $this->certificatePass) !== true) {

            throw new CertificateException('Could not read the certificate');
        }

        $certdata = openssl_x509_read($certs['cert']);
        $privkey  = openssl_pkey_get_private($certs['pkey'], $this->certificatePass);

        if (!empty($this->wwdrCertificatePath) && !file_exists($this->wwdrCertificatePath)) {

            throw new CertificateException('WWDR Intermediate Certificate does not exist');
        }

        openssl_pkcs7_sign(
            $paths['manifest'],
            $paths['signature'],
            $certdata,
            $privkey,
            [],
            PKCS7_BINARY | PKCS7_DETACHED,
            !empty($this->wwdrCertificatePath) ? $this->wwdrCertificatePath : null
        );

        $signature = file_get_contents($paths['signature']);
        $signature = $this->convertPEMtoDER($signature);
        file_put_contents($paths['signature'], $signature);

        return true;
    }

    /**
     * Creates .pkpass (zip archive)
     * Parameter: json-string, manifest file
     * Return: boolean, true on succes, false on failure
     *
     * @param $manifest
     *
     * @return bool
     */
    protected function createZip($manifest)
    {
        $paths = $this->paths();

        // Package file in Zip (as .pkpass)
        $zip = new ZipArchive();
        if (!$zip->open($paths['pkpass'], ZipArchive::CREATE)) {

            throw new ZipException(
                sprintf('Could not open %s with ZipArchive extension', basename($paths['pkpass']))
            );
        }

        $zip->addFile($paths['signature'], 'signature');
        $zip->addFromString('manifest.json', $manifest);
        $zip->addFromString('pass.json', $this->json);
        foreach ($this->files as $name => $path) {
            $zip->addFile($path, $name);
        }
        $zip->close();

        // Check if pass is created and valid
        if (!file_exists($paths['pkpass']) || filesize($paths['pkpass']) < 1) {
            $this->clean();

            throw new ZipException('Error while creating pass.pkpass. Check your Zip extension');
        }

        return true;
    }

    /**
     * Declares all paths used for temporary files.
     * @return array
     */
    protected function paths()
    {
        //Declare base paths
        $paths = [
            'pkpass'    => 'pass.pkpass',
            'signature' => 'signature',
            'manifest'  => 'manifest.json',
        ];

        //If trailing slash is missing, add it
        if (substr($this->tempPath, -1) != '/') {
            $this->tempPath = $this->tempPath . '/';
        }

        // Generate a unique sub-folder in the tempPath to support generating more
        // passes at the same time without erasing/overwriting each others files
        if (empty($this->uniqid)) {
            $this->uniqid = uniqid('PKPass', true);

            if (!is_dir($this->tempPath . $this->uniqid)) {
                mkdir($this->tempPath . $this->uniqid);
            }
        }

        //Add temp folder path
        foreach ($paths AS $pathName => $path) {
            $paths[$pathName] = $this->tempPath . $this->uniqid . '/' . $path;
        }

        return $paths;
    }

    /**
     * Removes all temporary files
     */
    protected function clean()
    {
        $paths = $this->paths();

        foreach ($paths AS $path) {
            if (file_exists($path)) {
                unlink($path);
            }
        }

        //Remove our unique temporary folder
        if (is_dir($this->tempPath . $this->uniqid)) {
            rmdir($this->tempPath . $this->uniqid);
        }

        return true;
    }


}
