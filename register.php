<?php

declare(strict_types=1);

// prevent direct request, defined in index.php
failsafe();

header('Content-Type: application/json');

require 'vendor/autoload.php';

use Webauthn\{
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    AuthenticatorSelectionCriteria
};

use Webauthn\PublicKeyCredential;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;



$data = file_get_contents('php://input');
applog(999,'data received: '.$data);


$csmFactory = new CeremonyStepManagerFactory();
$creationCSM = $csmFactory->creationCeremony();
$requestCSM = $csmFactory->requestCeremony();
$authenticatorAttestationResponseValidator = AuthenticatorAttestationResponseValidator::create(
    $creationCSM
);
$authenticatorAssertionResponseValidator = AuthenticatorAssertionResponseValidator::create(
    $requestCSM
);


$attestationStatementSupportManager = AttestationStatementSupportManager::create();
$attestationStatementSupportManager->add(NoneAttestationStatementSupport::create());
$factory = new WebauthnSerializerFactory($attestationStatementSupportManager);
$serializer = $factory->create();


try {
	$publicKeyCredential = $serializer->deserialize(
		$data,
		PublicKeyCredential::class,
		'json'
	);

} catch (\Trowable $e) {
	
        applog(401,'Registration failed: invalid data. '.$e->getMessage());
        http_response_code(401);
        echo json_encode([
                'success' => false,
                'error'   => 'Registration failed: invalid data. try again.'
        ]);
        mysqli_close($conn);
        exit();

}

try {
	$publicKeyCredentialCreationOptions = $serializer->deserialize(
		$_SESSION['registration_options'],
		PublicKeyCredentialCreationOptions::class,
		'json'
	);
} catch (\Throwable $e) {

	applog(401,'Registration failed: could not unserialize publicKeyCredentialCreationOptions: '.
		$_SESSION['registration_options']);
	        http_response_code(401);
        echo json_encode([
                'success' => false,
                'error'   => 'Registration failed: invalid data. try again.'
        ]);
        mysqli_close($conn);
        exit();
}

if (! hash_equals(
        $_SESSION['csrf_token'],
        $_SERVER['HTTP_X_CSRF_TOKEN'] ?? ''
    )) {
    applog(403,'Invalid CRRF Token');
    http_response_code(403);
    echo json_encode([
	'success' => false,
	'error'   => 'Invalid Token.'
    ]);
}

try {

	$publicKeyCredentialSource = $authenticatorAttestationResponseValidator->check(
		$publicKeyCredential->response,
		$publicKeyCredentialCreationOptions,
		MYDOMAINNAME
	);
	
} catch (\Throwable $e) {

	applog(401,'Registration failed: ' . $e->getMessage());
        http_response_code(401);
        echo json_encode([
                'success' => false,
                'error'   => 'Registration failed: ' . $e->getMessage()
        ]);
        mysqli_close($conn);
        exit();
}

/* success - store credential and mark user active */

$cred_source = $serializer->serialize(
	$publicKeyCredentialSource,
	'json',
	[
		AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
		JsonEncode::OPTIONS => JSON_THROW_ON_ERROR, 
	]
);



$sql = "UPDATE users SET status='Y' WHERE username='".
		mysqli_real_escape_string($conn,$_SESSION['username'])."'".
		" AND status='N'"; /* avoid X users */
mysqli_query($conn,$sql);

$sql = "INSERT INTO credentials (id,user_id,cred_source) VALUES ('".
	mysqli_real_escape_string($conn,$_SESSION['user_guid'])."',".
	intval($_SESSION['user_id']).",'".
	mysqli_real_escape_string($conn,$cred_source)."')";
mysqli_query($conn,$sql);

applog(200,'OK Authorized user '.$_SESSION['user_id'].' '.$_SESSION['username'].' '.$_SESSION['user_guid']);
echo json_encode(['success' => true]);

