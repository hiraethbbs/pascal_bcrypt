<?php

function bcrypt_assert_handler($file, $line, $code, $desc = null)
{
    if ($desc) {
        print $desc . PHP_EOL;
    }
}

assert_options(ASSERT_ACTIVE, 1);
assert_options(ASSERT_WARNING, 0);
assert_options(ASSERT_QUIET_EVAL, 0);
assert_options(ASSERT_CALLBACK, 'bcrypt_assert_handler');

$bsdPascalHash = '$2a$12$9NWTTEbRtjLNd4KdW.VtUekFA6pJ3DF23FqdvwwvMtoMD9zqdaZg2';
$bsdPascalHashFail = '$2a$12$9NWTTEbRtjLNd4KdW.VtUekFA6pJ3DF23FqdvwwvMtoMD9zqdaZg1';

$pascalHashesMT = [
  '$2y$10$kJgRFQ993paFLArmPE3gn.8yuUB/SRpaEw7lkJJ1oVqhWVIecI5nO',
  '$2y$11$kJgRFQ993paFLArmPE3gn.n9OJBeYd77RdOYnkdp9orILyaa5jDb6',
  '$2y$12$onWrpSgN3URAnmBJZkpqieH1QwbkDe5.RXInCYJG9MCtXL0yH6rxe',
  '$2y$13$AIbAdbn1wJ.Fc1dTNo/Ya..7mbUiSW91PRfn2d8.OYBkV5ddtjbge',
  '$2y$14$4Q96fpQzCJ6OrfBHW/vYn.DP2JFC/PzdPPKjdEuVs8JPMkYWRPAWy',
  '$2y$15$O2XqJxnSG0yOGuEgbgAGredSC7GPs72Bhm96cs0uWh79qhMVSroPy',
  '$2y$16$kRupPRj4D7V0wDJwOqvHPev4ZA8/C4upHvvvXpnCt7nnWi.6tyrKK',
];

$pascalHashesURandom = [
  '$2y$10$UCFG03qurE5eKhIIQRiMpu4Q1Y8xX2RgtHeB0TECbAsTW8bRrRmua',
  '$2y$11$rbUzZuxaYAN9I3encPoqGO6tzwUId9Ig2U2FQy.l2jjGCX9VqnP9q',
  '$2y$12$hDyyWY5qnGyE4he.2gbH3euopm.mOoMbnk78ZR9UgzjwaJp9BeGjK',
  '$2y$13$Vt527KNEnGTfUSX90HzP8un0WWYN038sOMrr/LdaP1GzWr77/j17.',
  '$2y$14$EitIDTZ4p2GxK63gDgSLAu63fGqkj0VxWmfaYERkpuXt.SCA1YLh2',
  '$2y$15$ELRZS1FLgo4.vVkJNqsnPeaKkUeHgIGLP42aHWHHc8ze8gUQviApO',
  '$2y$16$Y0QNc8vaJJY5mQO0IkN6oeAxEVjtnHYqk0WeWLPm7bRjxA7fWHRBG',
];

print PHP_EOL . 'Testing bsdPascalHash ... ' . str_repeat(PHP_EOL, 2);
print 'Testing : ' . $bsdPascalHash;
if (true === assert(password_verify('password', $bsdPascalHash), ' - Fail')) {
    print ' - Pass' . PHP_EOL;
}
print PHP_EOL . 'Testing bsdPascalHash for failure ... ' . str_repeat(PHP_EOL, 2);
print 'Testing : ' . $bsdPascalHashFail;
if (true === assert(!password_verify('password', $bsdPascalHashFail), ' - Fail')) {
    print ' - Pass' . PHP_EOL;
}

print PHP_EOL . 'Testing Pascal hashes MTRand ... ' . str_repeat(PHP_EOL, 2);
foreach ($pascalHashesMT as $pascalHash) {
    print 'Testing : ' . $pascalHash;
    if (true === assert(password_verify('password', $pascalHash), ' - Fail')) {
        print ' - Pass' . PHP_EOL;
    }
}

print PHP_EOL . 'Testing Pascal hashes urandom ... ' . str_repeat(PHP_EOL, 2);
foreach ($pascalHashesURandom as $pascalHash) {
    print 'Testing : ' . $pascalHash;
    if (true === assert(password_verify('password', $pascalHash), ' - Fail')) {
        print ' - Pass' . PHP_EOL;
    }
}

print PHP_EOL . 'Testing password_needs_rehash ... ' . str_repeat(PHP_EOL, 2);
foreach ($pascalHashesURandom as $pascalHash) {
    print 'Testing : ' . $pascalHash;
    if (true === assert(
        !password_needs_rehash(
            $pascalHash,
            PASSWORD_BCRYPT,
            ['cost' => substr($pascalHash, 4, 2)]
        ),
        ' - Fail'
    )
        ) {
        print ' - Pass' . PHP_EOL;
    }
}
print PHP_EOL;
