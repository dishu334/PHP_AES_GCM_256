<?php

$plaintext = '{"user_id": 9999323,"username":"Divyansh Rajput"}';
//generating random 32 byte Base64 encoded AES key
$keyLength = 32;
$aesKey = openssl_random_pseudo_bytes($keyLength);
if ($aesKey === false) {
die("Failed to generate a secure AES key.");
}

$key = $aesKey;

//generating timestamp for aad
$t = explode(" ", microtime());
$timestamp_same = date("Y-m-d\TH:i:s", $t[1]) . substr((string) $t[0], 1, 4);
$aad = substr($timestamp_same, 0, 16);

//Encrypting Request
$encrypted = aesGcmEncrypt($plaintext, $key, $aad);
//echo "Encrypted Data: " . $encrypted . PHP_EOL;

//Decrypting above encrypted Request/Response
$decrypted = aesGcmDecrypt($encrypted, $key);
echo "Decrypted Data: " . $decrypted . PHP_EOL;

/**

This PHP script is used to generates Encrypted Payload
*/
function aesGcmEncrypt($plaintext, $key, $aad = "", $tagLength = 16)
{
// Generate a random initialization vector (IV)
$iv = substr($key, 0, 12); // GCM mode requires a 12-byte IV

// Encrypt the data
$ciphertext = openssl_encrypt(
$plaintext,
"aes-256-gcm",
$key,
OPENSSL_RAW_DATA,
$iv,
$tag,
$aad,
$tagLength
);

// Return the IV, ciphertext, and authentication tag as a combined string
return base64_encode($ciphertext . $tag . $aad);
}

/**

This PHP script is used to generates Decrypted Payload
*/
function aesGcmDecrypt($ciphertextBase64, $key, $aad = "", $tagLength = 16)
{
// Decode the base64 encoded string
$ciphertextCombined = base64_decode($ciphertextBase64);

// Extract the IV, ciphertext, and tag
$iv = substr($key, 0, 12);

$ciphertext = substr($ciphertextCombined, 0, -($tagLength + 16)); // The next bytes are the ciphertext

$tagwithaad = substr($ciphertextCombined, -($tagLength + 16));
$tagwithoutaad = substr($tagwithaad, 0, 16);
$aad = substr($tagwithaad, -16);

// Decrypt the data
$plaintext = openssl_decrypt(
$ciphertext,
"aes-256-gcm",
$key,
OPENSSL_RAW_DATA,
$iv,
$tagwithoutaad,
$aad
);
return $plaintext;
}
?>
