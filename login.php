<?php

declare(strict_types=1);

header('Content-Type: application/json');

require 'vendor/autoload.php';

use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;

$username='';
$user_id=0;
$user_guid='';
$displayName='';
$request_options='';

if (isset($_SESSION['username']))
{
	$username = filter_var(strtolower($_SESSION['username']), FILTER_VALIDATE_EMAIL);
}
if (isset($_SESSION['user_id']))
{
	$user_id = intval($_SESSION['user_id']);
}
if (isset($_SESSION['user_guid']))
{
	$user_guid = $_SESSION['user_guid'];
}
if (isset($_SESSION['displayName']))
{
	$displayName = $_SESSION['displayName'];
}
if (isset($_SESSION['request_options']))
{
	$request_options = $_SESSION['request_options'];
}

$err=false;
if (strlen($username)<7) $err=true;
if ($user_id<10) $err=true;
if (strlen($user_guid)<36) $err=true;
if (strlen($displayName)<1) $err=true;
if (strlen($request_options)<1) $err=true;

if ($err)
{
	http_response_code(401);
	applog(401,"Invalid session data on login");
	echo json_encode(['success' => false, 'error' => 'Invalid session. Please try again.']);
	mysqli_close($conn);
	exit();
}

$attestationStatementSupportManager = AttestationStatementSupportManager::create();
$attestationStatementSupportManager->add(NoneAttestationStatementSupport::create());
$factory = new WebauthnSerializerFactory($attestationStatementSupportManager);
$serializer = $factory->create();

$data = file_get_contents('php://input');


if ($data!='') {

	applog(999,$data);

	$challenge = base64_decode($request_options);

                $registeredAuthenticators = array();
                $sql = "SELECT users.id, users.display_name, ".
                        "credentials.id as cred_id, credentials.cred_source ".
                        "FROM users LEFT JOIN credentials ON users.id=credentials.user_id ".
                        "WHERE users.username='".mysqli_real_escape_string($conn,$username)."'";
                $res = mysqli_query($conn,$sql);
                if (mysqli_num_rows($res)>0)
                {
                        while ($row = mysqli_fetch_array($res))
                        {
                                if ($row['cred_source']!='')
                                {
                                        $publicKeyCredentialSource = $serializer->deserialize(
                                                $row['cred_source'],
                                                PublicKeyCredentialSource::class,
                                                'json'
                                        );
                                        $registeredAuthenticators[]=$publicKeyCredentialSource;
                                }
                        }
                        $allowedCredentials = array_map(
                                static function (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor {
                                        return $credential->getPublicKeyCredentialDescriptor();
                                },
                                $registeredAuthenticators
                        );
		}
		mysqli_free_result($res);

        $publicKeyCredentialRequestOptions =
	        PublicKeyCredentialRequestOptions::create(
                challenge: $challenge,
                allowCredentials: $allowedCredentials,
                userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED
        );

	try {
		$publicKeyCredential = $serializer->deserialize($data, PublicKeyCredential::class, 'json');
		if (!$publicKeyCredential->response instanceof AuthenticatorAssertionResponse) {
			http_response_code(404);
			applog(401,"Invalid token data (deserialize failed) on login");
			echo json_encode(['success' => false, 'error' => 'Login failed. Please try again.']);
			mysqli_close($conn);
			exit();
		} else {
			$authenticatorAssertionResponse = $publicKeyCredential->response;
		}
	} catch (\Throwable $e) {
		http_response_code(404);
		applog(401,"Invalid token data parsed on login");
		echo json_encode(['success' => false, 'error' => 'Login failed. Please try again.']);
		mysqli_close($conn);
		exit();
	}
	
	$pd=json_decode($data,true);
	if (isset($pd['id']))
	{
		$sql = "SELECT cred_source FROM credentials WHERE cred_source LIKE '%".
			mysqli_real_escape_string($conn,$pd['id'])."%' AND ".
			"id='".$user_guid."'";
		applog(999,$sql);
		$res = mysqli_query($conn,$sql);
		if (mysqli_num_rows($res)<1)
		{
			http_response_code(404);
			applog(401,"No key found in database on login");
			echo json_encode(['success' => false, 'error' => 'Login failed. Please try again.']);
			mysqli_free_result($res);
			mysqli_close($conn);
			exit();
		} else {
			$row = mysqli_fetch_array($res);
                        $publicKeyCredentialSource = $serializer->deserialize(
	                        $row['cred_source'],
                                PublicKeyCredentialSource::class,
                                'json'
                        );
		}
	} else {
                http_response_code(404);
                applog(401,"No ID: Invalid token data parsed on login");
                echo json_encode(['success' => false, 'error' => 'Login failed. Please try again.']);
                mysqli_close($conn);
                exit();
	}
	mysqli_free_result($res);

	$csmFactory = new CeremonyStepManagerFactory();
	$requestCSM = $csmFactory->requestCeremony();

	$authenticatorAssertionResponseValidator = AuthenticatorAssertionResponseValidator::create(
		$requestCSM
	);

	if (!$publicKeyCredential->response instanceof AuthenticatorAssertionResponse) {

                http_response_code(404);
                applog(401,"Invalid Response");
                echo json_encode(['success' => false, 'error' => 'Login failed. Please try again.']);
                mysqli_close($conn);
                exit();

	}

        $userEntity = PublicKeyCredentialUserEntity::create(
                                $username,
                                $user_guid,
                                $displayName
                        );

	
	try {
		$publicKeyCredentialSource = $authenticatorAssertionResponseValidator->check(
			$publicKeyCredentialSource,
			$authenticatorAssertionResponse,
			$publicKeyCredentialRequestOptions,
			MYDOMAINNAME,
			$userEntity?->id
		);
	} catch (\Throwable $e) {
                http_response_code(404);
                applog(401,"ResponseValidator check: Invalid token check on login: ".$e->getMessage());
                echo json_encode(['success' => false, 'error' => 'Login failed. Please try again.']);
                mysqli_free_result($res);
                mysqli_close($conn);
                exit();
	}

        if ($publicKeyCredentialSource === null) {
 		http_response_code(404);
                applog(404,"No pkCredentialSource: Invalid token on login");
                echo json_encode(['success' => false, 'error' => 'Credentials not found. Please try again.']);
                mysqli_close($conn);
                exit();
        }

	
	$cred_source = $serializer->serialize(
	        $publicKeyCredentialSource,
		 'json',
		[
			AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
			JsonEncode::OPTIONS => JSON_THROW_ON_ERROR,
		]
	);


	//store with any updates from auth device
	$sql = "UPDATE credentials SET cred_source='".
		mysqli_real_escape_string($conn,$cred_source)."' ".
		"WHERE user_id=".intval($user_id)." AND ".
		"id = '".mysqli_real_escape_string($conn,$user_guid)."' AND ".
		"cred_source LIKE '%".mysqli_real_escape_string($conn,$pd['id'])."%'";
	mysqli_query($conn,$sql);
		

	$sql = "INSERT INTO logins (id,guid,ip) VALUES (NULL,'".
		mysqli_real_escape_string($conn,$user_guid)."','".
		mysqli_real_escape_string($conn,$_SERVER['REMOTE_ADDR'])."')";
	mysqli_query($conn,$sql);

	applog(200,'OK Login: Authorized user '.$_SESSION['user_id'].' '.$_SESSION['username'].' '.$_SESSION['user_guid']);
	echo json_encode(['success' => true]);
} else {
	http_response_code(404);
	applog(401,"Invalid data sent to login");
	echo json_encode(['success' => false, 'error' => 'Login failed. Please try again.']);
	mysqli_close($conn);
	exit();
}


