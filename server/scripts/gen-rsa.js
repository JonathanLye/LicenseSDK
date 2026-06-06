const { generateKeyPairSync } = require('crypto');
const { writeFileSync } = require('fs');

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Write private key to .env
const privB64 = Buffer.from(privateKey).toString('base64');
const envLine = `RSA_PRIVATE_KEY=${privB64}`;
writeFileSync('.env-rsa', envLine);
console.log('Private key written to .env-rsa — append this line to your .env');

// Write public key fragments for SDK
const pubB64 = Buffer.from(publicKey).toString('base64');
const n = Math.ceil(pubB64.length / 6);
const parts = [];
for (let i = 0; i < 6; i++) {
  parts.push(pubB64.slice(i * n, (i + 1) * n));
}

let csCode = '';
parts.forEach((p, i) => {
  csCode += `        var p${i + 1} = "${p}";\n`;
});
csCode += `        _pubKeyPem = Encoding.UTF8.GetString(Convert.FromBase64String(${parts.map((_, i) => 'p' + (i + 1)).join(' + ')}));`;

writeFileSync('sdk-fragments.txt', csCode);
console.log('\nPublic key — paste these fragments into RsaVerifier.cs (replace existing p1-p6):');
console.log(csCode);
