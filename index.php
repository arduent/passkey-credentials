<?php

define('MYSERVICENAME','My Fancy Fun Example');
define('MYDOMAINNAME','myfancyfun.example.com');

$conn=mysqli_connect('127.0.0.1','user','pass','database') or die('no connecto');

session_set_cookie_params([
  'lifetime' => 0, 
  'path'     => '/',
  'domain'   => MYDOMAINNAME,
  'secure'   => true, 
  'httponly' => true,
  'samesite' => 'Strict'
]);

session_start();

$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

/* naughty sessions*/
if (isset($_SESSION['ua']) && ($_SESSION['ua'] !== $_SERVER['HTTP_USER_AGENT'])) {
    session_destroy();
}

/* check if logged in */

$authenticated = false;
$displayName = '';

/* check if logged in */

$authenticated = false;
$displayName = '';

if (isset($_SESSION['user_guid']))
{
        $sql = "SELECT id FROM logins WHERE guid='".
                mysqli_real_escape_string($conn,$_SESSION['user_guid'])."' AND ".
                "active='Y'";
        $res = mysqli_query($conn,$sql);
        if (mysqli_num_rows($res)>0)
        {
                mysqli_free_result($res);
                $authenticated = true;
                $sql = "SELECT display_name FROM users WHERE guid='".
                        mysqli_real_escape_string($conn,$_SESSION['user_guid'])."'";
                $res = mysqli_query($conn,$sql);
                $row = mysqli_fetch_array($res);
                $displayName = $row['display_name'];
        }       
        mysqli_free_result($res);
}

$layout = file_get_contents('layout.html');
if ($authenticated && ($displayName!=''))
{
        $layout = str_replace('<!--Display Name-->',
                '            <li class="nav-item dropdown">
              <a class="nav-link dropdown-toggle" href="#" id="navbarDropdown" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                '.htmlentities($displayName).'
              </a>
              <ul class="dropdown-menu" aria-labelledby="navbarDropdown">
                <li><a class="dropdown-item hi-history" href="/account">Account</a></li>
              </ul>
            </li>',$layout);
}


function failsafe()
{
        return;
}

function applog($code,$msg)
{
        $f=fopen('log/.app.txt','a');
        fwrite($f,date('Y-m-d g:i:s')."\t".$_SERVER['REMOTE_ADDR']."\t[".$code."]\t".$msg."\t".$_SERVER['REQUEST_URI']."\n");
        fclose($f);
}

$content = '';
$title = '';
$active = '';
$page = 'home';

if (isset($_GET['req']))
{
        $page = str_replace('.html','',$_GET['req']);
        $page = str_replace('.','',$page);
        $page = str_replace('/','',$page);
}

switch ($page)
{
        case 'account':
                include('account.php');
                $title = 'Your Account - ';
                break;

        case 'pk-login':
                $x=file_get_contents('pk-login.html');
                $csrf = '<meta name="csrf-token" content="'.$_SESSION['csrf_token'].'">';
                $s=explode('<!--SPLIT-->',$x);
                $layout = str_replace('</head>',$csrf."\n".array_shift($s)."\n".'</head>',$layout);
                $content = array_pop($s);
                $title = 'Login - ';
                break;

        case 'pk-reg':
                $x=file_get_contents('pk-reg.html');

                $csrf = '<meta name="csrf-token" content="'.$_SESSION['csrf_token'].'">';
                $s=explode('<!--SPLIT-->',$x);
                $layout = str_replace('</head>',$csrf."\n".array_shift($s)."\n".'</head>',$layout);
                $content = array_pop($s);
                $title = 'Register Passkey - ';
                break;

        case 'login':
                include('login.php');
                mysqli_close($conn);
                exit();

        case 'login-op':
                include('login-op.php');
                mysqli_close($conn);
                exit();

        case 'register':
                include('register.php');
                mysqli_close($conn);
                exit();

        case 'registration-op':
                include('registration-op.php');
                mysqli_close($conn);
                exit();

        default:
                $content = file_get_contents('home.html');
                $active = 'hi-home';
                break;
}

if ($title!='') $layout = str_replace('<title>','<title>'.$title,$layout);
if ($active!='') $layout = str_replace($active,'active',$layout);
$html = str_replace('<!--Content-->',$content,$layout);
echo $html;
mysqli_close($conn);
exit();

