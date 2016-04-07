<?php
use PKPass\Exception\PKPassException;
use PKPass\PKPass;

require('../PKPass.php');

// Top-Level Keys http://developer.apple.com/library/ios/#documentation/userexperience/Reference/PassKit_Bundle/Chapters/TopLevel.html
$standardKeys         = [
    'description'        => 'Demo pass',
    'formatVersion'      => 1,
    'organizationName'   => 'Flight Express',
    'passTypeIdentifier' => 'pass.com.apple.test', // 4. Set to yours
    'serialNumber'       => '123456',
    'teamIdentifier'     => 'AGK5BZEN3E'           // 4. Set to yours
];
$associatedAppKeys    = [];
$relevanceKeys        = [];
$styleKeys            = [
    'boardingPass' => [
        'primaryFields'   => [
            [
                'key'   => 'origin',
                'label' => 'San Francisco',
                'value' => 'SFO',
            ],
            [
                'key'   => 'destination',
                'label' => 'London',
                'value' => 'LHR',
            ],
        ],
        'secondaryFields' => [
            [
                'key'   => 'gate',
                'label' => 'Gate',
                'value' => 'F12',
            ],
            [
                'key'   => 'date',
                'label' => 'Departure date',
                'value' => '07/11/2012 10:22',
            ],
        ],
        'backFields'      => [
            [
                'key'   => 'passenger-name',
                'label' => 'Passenger',
                'value' => 'John Appleseed',
            ],
        ],
        'transitType'     => 'PKTransitTypeAir',
    ],
];
$visualAppearanceKeys = [
    'barcode'         => [
        'format'          => 'PKBarcodeFormatQR',
        'message'         => 'Flight-GateF12-ID6643679AH7B',
        'messageEncoding' => 'iso-8859-1',
    ],
    'backgroundColor' => 'rgb(107,156,196)',
    'logoText'        => 'Flight info',
];
$webServiceKeys       = [];

// Merge all pass data and set JSON for $pass object
$passData = array_merge(
    $standardKeys,
    $associatedAppKeys,
    $relevanceKeys,
    $styleKeys,
    $visualAppearanceKeys,
    $webServiceKeys
);
try {
    $pass = new PKPass();

    $pass->setCertificate('../Certificate.p12');  // 1. Set the path to your Pass Certificate (.p12 file)
    $pass->setCertificatePassword('test123');     // 2. Set password for certificate
    $pass->setWwdrCertificatePath('../AppleWWDRCA.pem'); // 3. Set the path to your WWDR Intermediate certificate (.pem file)

    $pass->setJson(json_encode($passData, JSON_FORCE_OBJECT));

    // Add files to the PKPass package
    $pass->addFile('icon.png');
    $pass->addFile('icon@2x.png');
    $pass->addFile('logo.png');

    $pass->create(true);
} catch (PKPassException $exception) {
    echo "Error {$exception->getMessage()}";
}
