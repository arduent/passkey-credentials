<?php

declare(strict_types=1);

// prevent direct request, defined in index.php
failsafe();

header('Content-Type: application/json');

require 'vendor/autoload.php';

use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;

$attestationStatementSupportManager = AttestationStatementSupportManager::create();
$attestationStatementSupportManager->add(NoneAttestationStatementSupport::create());
$factory = new WebauthnSerializerFactory($attestationStatementSupportManager);
$serializer = $factory->create();

$r = new \Random\Randomizer(); /* for array_shuffle */

function base64url_encode($data) {

  return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');

}

function build_stub()
{
	$stub = '{"publicKeyCredentialId":"<!--ID-->","type":"public-key","transports":[],"attestationType":"none","trustPath":[],"aaguid":"00000000-0000-0000-0000-000000000000","credentialPublicKey":"<!--PK-->","userHandle":"<!--HANDLE-->","counter":<!--COUNTER-->,"backupEligible":false,"backupStatus":false,"uvInitialized":true}';

	/*
		<!--COUNTER-->
		int
	*/

	$cnt=random_int(1,500);
	$stub = str_replace('<!--COUNTER-->',(string)$cnt,$stub);

	/*
		<!--ID--> 64 bytes
	*/

	$id=base64url_encode(random_bytes(64));
	$stub = str_replace('<!--ID-->',$id,$stub);

	/*
		<!--PK--> 77 bytes
	*/

	$pk=base64url_encode(random_bytes(77));
	$stub = str_replace('<!--PK-->',$pk,$stub);

	/*
		<!--HANDLE--> 36 bytes
	*/

	$handle=base64url_encode(random_bytes(36));
	$stub = str_replace('<!--HANDLE-->',$handle,$stub);

	return($stub);
}

$pd = json_decode(file_get_contents('php://input'), true);

if (is_array($pd))
{
        foreach ($pd as $k=>$v)
        {
                if (gettype($v)=='string')
                {
                        $pd[$k]=trim($v);
                }
        }
}


if (isset($pd['username']))
{
	$username = filter_var($pd['username'], FILTER_VALIDATE_EMAIL);
	if ($username!='')
	{

		$registeredAuthenticators = array();
		$sql = "SELECT users.id, users.display_name, ".
			"credentials.id as cred_id, credentials.cred_source ".
			"FROM users LEFT JOIN credentials ON users.id=credentials.user_id ".
			"WHERE users.username='".mysqli_real_escape_string($conn,$username)."'";
		$res = mysqli_query($conn,$sql);
		if (mysqli_num_rows($res)>0)
		{
			$user_id = '';
			$user_guid = '';
			$displayName = '';
			
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
				$user_id = $row['id'];
				$user_guid = $row['cred_id'];
				$displayName = $row['display_name'];
			}

                        if (count($registeredAuthenticators)<1)
                        {
                                http_response_code(404);
                                applog(404,"No authenticators found for ".$username);
                                echo json_encode(['success' => false, 'error' => 'Credentials not found']);
                                mysqli_close($conn);
                                exit();
                        }

                        $_SESSION['username']      = $username;
                        $_SESSION['user_id']       = $user_id;
                        $_SESSION['user_guid']     = $user_guid;
                        $_SESSION['displayName']   = $displayName;


			/* add random credential sources to deter key enumeration
				this is mentioned in the doc however it seems 
				a few requests would reveal the 'static' tokens
			*/
			$rd = random_int(3,16);
			for ($i=0;$i<$rd;$i++)
			{
				$src = build_stub();
				$publicKeyCredentialSource = $serializer->deserialize(
                                                $src,
                                                PublicKeyCredentialSource::class,
                                                'json'
                                );
                                $registeredAuthenticators[]=$publicKeyCredentialSource;
			}	

			$randomizedRegisteredAuthenticators = $r->shuffleArray($registeredAuthenticators);

			$allowedCredentials = array_map(
				static function (PublicKeyCredentialSource $credential): PublicKeyCredentialDescriptor {
					return $credential->getPublicKeyCredentialDescriptor();
				},
				$randomizedRegisteredAuthenticators
			);

			$challenge = random_bytes(32);

			$publicKeyCredentialRequestOptions =
				PublicKeyCredentialRequestOptions::create(
				challenge: $challenge,
				allowCredentials: $allowedCredentials,
				userVerification: PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED
			);

		        $jsonObject = $serializer->serialize(
               			$publicKeyCredentialRequestOptions,
                		'json',
                		[
                       			AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
                        		JsonEncode::OPTIONS => JSON_THROW_ON_ERROR, // Optional
                		]
        		);

			$_SESSION['request_options']=base64_encode($challenge);

		        applog(200,'Sent credential request options: '.$username);
        		applog(999,$jsonObject);
        		echo $jsonObject;

		}
		mysqli_free_result($res);

	} else {

		http_response_code(404);
		applog(404,'Credentials Not Found for user: <'.$username.'>');
		echo json_encode(['success' => false, 'error' => 'Credentials not found']);
		mysqli_close($conn);
		exit();
	}
} else {
	http_response_code(404);
	applog(404,'No username sent for login.');
	echo json_encode(['success' => false, 'error' => 'Credentials not found']);
	mysqli_close($conn);
	exit();
}

