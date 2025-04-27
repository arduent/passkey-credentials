<?php

declare(strict_types=1);

/* prevent direct request, defined in index.php */
failsafe();

header('Content-Type: application/json');

require 'vendor/autoload.php';

use Webauthn\{
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    AuthenticatorSelectionCriteria
};

use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Symfony\Component\Serializer\Encoder\JsonEncode;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;


function guidv4($data = null) {
    $data = $data ?? random_bytes(16);
    assert(strlen($data) == 16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}

$sql = "SELECT COUNT(*) FROM users WHERE ip='".
	mysqli_real_escape_string($conn,$_SERVER['REMOTE_ADD'])."' AND status='N'";
$res = mysqli_query($conn,$sql);
$row = mysqli_fetch_array($res);
if (intval($row[0])>1)
{
	applog(401,'Too many unconfirmed accounts from ip: '.$_SERVER['REMOTE_ADD']);
	http_response_code(401);
        echo json_encode([
	              'success' => false,
                      'error'   => 'Registration failed: Too many requests. Please try again later or contact support.'
	]);
        mysqli_free_result($res);
        mysqli_close($conn);
        exit();
}
mysqli_free_result($res);


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

/* check input */

$err=array();

$username = '';
if (isset($pd['username']))
{
	$username = filter_var(strtolower($pd['username']), FILTER_VALIDATE_EMAIL);
}

if (strlen($pd['username'])<7)
{
	$err[]='Please provide your valid Email Address';
}
if (!isset($pd['firstName']) || (strlen($pd['firstName'])<1))
{
	$err[]='Please provide your First Name';
}
if (!isset($pd['lastName']) || (strlen($pd['lastName'])<1))
{
	$err[]='Please provide your Last Name';
}
if (!isset($pd['phone']) || (strlen($pd['phone'])<10))
{
	$err[]='Please provide your Phone Number including area code';
}
if (!isset($pd['address']) || (strlen($pd['address'])<5))
{
	$err[]='Please provide your Street Address';
}
if (!isset($pd['city']) || (strlen($pd['city'])<1))
{
	$err[]='Please provide your City';
}
if (!isset($pd['state']) || (strlen($pd['state'])<1))
{
	$err[]='Please provide your State';
}
if (!isset($pd['zip']) || (strlen($pd['zip'])<5))
{
	$err[]='Please provide your Zip Code';
}

if (count($err)<1)
{
	$displayName = $pd['firstName'];

	/* check if user already exists */

	$sql = "SELECT id FROM users WHERE username='".
        	mysqli_real_escape_string($conn,$username)."'";
	$res = mysqli_query($conn,$sql);
	if (mysqli_num_rows($res)>0)
	{
		/* user already exists in database */

	        applog(401,'Username <'.$username.'> exists');
    		http_response_code(401);
    		echo json_encode([
            		'success' => false,
            		'error'   => 'Registration failed: User already exists.'
        	]);
    		mysqli_free_result($res);
    		mysqli_close($conn);
    		exit();
	}

	/* create user */

	$guid = guidv4();

	$sql = "INSERT INTO users (id,guid,username,display_name,status,ip) VALUES (NULL,'".
		mysqli_real_escape_string($conn,$guid)."','".
                mysqli_real_escape_string($conn,$username)."','".
                mysqli_real_escape_string($conn,$displayName)."','N','". /* status=N */
		mysqli_real_escape_string($conn,$_SERVER['REMOTE_ADDR'])."')";

	mysqli_query($conn,$sql);

	$cid = mysqli_insert_id($conn);

	/* user_info entry */

	$sql = "INSERT INTO user_info (user_id,email,first_name,last_name,".
		"phone,company,nonprofit,title,website,address,city,state,".
		"zip_code,comments,auth_passkey,auth_totp) VALUES (".$cid.",'".
			mysqli_real_escape_string($conn, $username)."','".
			mysqli_real_escape_string($conn, $pd['firstName'])."','".
			mysqli_real_escape_string($conn, $pd['lastName'])."','".
			mysqli_real_escape_string($conn, $pd['phone'])."','".
			mysqli_real_escape_string($conn, $pd['company'])."','".
			mysqli_real_escape_string($conn, $pd['nonprofit'])."','".
			mysqli_real_escape_string($conn, $pd['title'])."','".
			mysqli_real_escape_string($conn, $pd['website'])."','".
			mysqli_real_escape_string($conn, $pd['address'])."','".
			mysqli_real_escape_string($conn, $pd['city'])."','".
			mysqli_real_escape_string($conn, $pd['state'])."','".
			mysqli_real_escape_string($conn, $pd['zip'])."','".
			mysqli_real_escape_string($conn, $pd['comments'])."','".
			mysqli_real_escape_string($conn, $pd['authPasskey'] ? 'Y' : 'N')."','".
			mysqli_real_escape_string($conn, $pd['authTOTP'] ? 'Y' : 'N')."')";
	mysqli_query($conn,$sql);

	/* create Passkey auth */
	/* can add 4th parament for user icon but should be 128 bytes or less */

	$userEntity = PublicKeyCredentialUserEntity::create(
  	  			$username,
				$guid,
    				$displayName
			);

	/* supposedly icon must be 128 bytes or less (is that mono 8x8 pixel?) */
	$rpEntity = PublicKeyCredentialRpEntity::create(
		MYSERVICENAME,
		MYDOMAINNAME,
		'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAAXNSR0IArs4c6QAAAZtJREFUOE/N00FIk3EYx/Hv62s4wSIvitv0kmNzEw+dxgYRejEFRTKoS0VoTDZiIAM7TD04hiQKLzIkaRQIakEQ4g67BGO71qF42yRJeBnSQCbRwZlvf2GJoOMNpUM+1/+PD/+H53kkIYTgH0q6oICmwcIC2x83qELQeN0BIyNgsVQ0W9lCMgk+HwQCBD95qZYFM440xGKwuAhdXSeQU4CAtSi032Orrgmncx+pSpBTTViLGmRfQ28IpEvHyEnglcKvGzfRzB1MTBVYmmooBx9OFJh82oA1n0VOr8P9UQPA40F7scTmFTO93iKdPTJI8D6hk8jUc21nC4v/MaRSBoDbzdeXK2R+XCafL5FYlsvBW3cPaGk24a4tYvM9gHTGAAgE+NLsZPjDbTZUnUdPqsvBuHKArU3meccqrp1vMDdnAORyPOuO8HMoRL/fianmzw/2Sjrv5j9TF58llAxDa6sBAOjLK0jjYb6PhdkdGAQhuPr2DY3TEUQ0inxn8G9jPHpTVVAURJ8L9N9IiSwEg2C3n2GRznlY//+YDgGkMLrR1TVUhAAAAABJRU5ErkJggg=='
	);

	$publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions::create(
		rp:                      $rpEntity,
		user:                    $userEntity,
		challenge:               random_bytes(16),
		pubKeyCredParams:        [],
		authenticatorSelection:  new AuthenticatorSelectionCriteria(),
		attestation:             'none',
		timeout:                 60000,
		excludeCredentials:      []
		// extensions: 
	);

	
	$attestationStatementSupportManager = AttestationStatementSupportManager::create();
	$attestationStatementSupportManager->add(NoneAttestationStatementSupport::create());
	$factory = new WebauthnSerializerFactory($attestationStatementSupportManager);
	$serializer = $factory->create();

	$jsonObject = $serializer->serialize(
		$publicKeyCredentialCreationOptions,
		'json',
		[
			AbstractObjectNormalizer::SKIP_NULL_VALUES => true,
			JsonEncode::OPTIONS => JSON_THROW_ON_ERROR, // Optional
    		]
	);
	
	$options = $jsonObject;

	/* save session data */

	$_SESSION['user_id'] = $cid;
	$_SESSION['user_guid'] = $guid;
	$_SESSION['username'] = $username;
	$_SESSION['user_entity'] = $userEntity;
	$_SESSION['registration_options'] = $jsonObject;
	$_SESSION['displayName'] = $displayName;

	applog(200,'Create user ok: '.$username);
	applog(999,$options);
	echo $options;

} else {

	/* error out */

	applog(401,'Post data error: '.json_encode($err).' '.json_encode($pd));
	http_response_code(401);
	echo json_encode([
		'success' => false,
		'error'   => 'Registration failed: '.join(', ',$err)
	]);
	mysqli_close($conn);
	exit();
}

