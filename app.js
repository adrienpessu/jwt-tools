import * as jose from 'https://cdn.jsdelivr.net/npm/jose@5.2.0/+esm';

// DOM Elements
const encodedJwtInput = document.getElementById('encoded-jwt');
const headerJsonInput = document.getElementById('header-json');
const payloadJsonInput = document.getElementById('payload-json');
const algorithmSelect = document.getElementById('algorithm');
const secretInput = document.getElementById('secret');
const encodeBtn = document.getElementById('encode-btn');
const decodeBtn = document.getElementById('decode-btn');
const statusMessage = document.getElementById('status-message');

// Default values
const defaultSecret = 'your-256-bit-secret';
const defaultHeader = { alg: 'HS256', typ: 'JWT' };
const defaultPayload = {
    sub: '1234567890',
    name: 'John Doe',
    iat: 1516239022
};

// Initialize with default values
function initializeDefaults() {
    headerJsonInput.value = JSON.stringify(defaultHeader, null, 2);
    payloadJsonInput.value = JSON.stringify(defaultPayload, null, 2);
    secretInput.value = defaultSecret;
    
    // Encode with defaults
    encodeJWT();
}

// Show status message
function showStatus(message, type = 'success') {
    statusMessage.textContent = message;
    statusMessage.className = `status-message ${type}`;
}

// Hide status message
function hideStatus() {
    statusMessage.className = 'status-message';
}

// Validate JSON
function isValidJSON(str) {
    try {
        JSON.parse(str);
        return true;
    } catch (e) {
        return false;
    }
}

// Decode base64url manually (fallback)
function base64urlDecode(str) {
    // Replace URL-safe characters
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    // Add padding if necessary
    while (str.length % 4) {
        str += '=';
    }
    try {
        return atob(str);
    } catch (e) {
        throw new Error('Invalid base64url string');
    }
}

// Encode base64url manually
function base64urlEncode(str) {
    return btoa(str)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

// Decode JWT manually (for display purposes)
async function decodeJWT() {
    try {
        const token = encodedJwtInput.value.trim();
        
        if (!token) {
            showStatus('Please enter a JWT token', 'warning');
            encodedJwtInput.classList.remove('valid', 'invalid');
            return;
        }

        const parts = token.split('.');
        
        if (parts.length !== 3) {
            showStatus('Invalid JWT format. A JWT should have 3 parts separated by dots.', 'error');
            encodedJwtInput.classList.remove('valid');
            encodedJwtInput.classList.add('invalid');
            return;
        }

        // Decode header
        const headerStr = base64urlDecode(parts[0]);
        const header = JSON.parse(headerStr);
        
        // Decode payload
        const payloadStr = base64urlDecode(parts[1]);
        const payload = JSON.parse(payloadStr);

        // Update UI
        headerJsonInput.value = JSON.stringify(header, null, 2);
        payloadJsonInput.value = JSON.stringify(payload, null, 2);
        
        // Update algorithm selector
        if (header.alg) {
            algorithmSelect.value = header.alg;
        }

        encodedJwtInput.classList.add('valid');
        encodedJwtInput.classList.remove('invalid');
        
        showStatus('JWT decoded successfully!', 'success');
        
    } catch (error) {
        console.error('Decode error:', error);
        showStatus(`Decoding failed: ${error.message}`, 'error');
        encodedJwtInput.classList.remove('valid');
        encodedJwtInput.classList.add('invalid');
    }
}

// Encode JWT using panva/jose
async function encodeJWT() {
    try {
        // Validate inputs
        if (!isValidJSON(headerJsonInput.value)) {
            showStatus('Invalid JSON in header', 'error');
            return;
        }
        
        if (!isValidJSON(payloadJsonInput.value)) {
            showStatus('Invalid JSON in payload', 'error');
            return;
        }

        const header = JSON.parse(headerJsonInput.value);
        const payload = JSON.parse(payloadJsonInput.value);
        const algorithm = algorithmSelect.value;
        const secret = secretInput.value || defaultSecret;

        // Update header algorithm
        header.alg = algorithm;
        headerJsonInput.value = JSON.stringify(header, null, 2);

        let token;

        // Handle different algorithm types
        if (algorithm.startsWith('HS')) {
            // HMAC algorithms
            const secretKey = new TextEncoder().encode(secret);
            token = await new jose.SignJWT(payload)
                .setProtectedHeader({ alg: algorithm, typ: header.typ || 'JWT' })
                .sign(secretKey);
                
        } else if (algorithm.startsWith('RS') || algorithm.startsWith('PS') || algorithm.startsWith('ES')) {
            // RSA, RSA-PSS, or ECDSA algorithms require key pairs
            try {
                // Try to parse as PEM key
                if (secret.includes('BEGIN')) {
                    const privateKey = await jose.importPKCS8(secret, algorithm);
                    token = await new jose.SignJWT(payload)
                        .setProtectedHeader({ alg: algorithm, typ: header.typ || 'JWT' })
                        .sign(privateKey);
                } else {
                    showStatus(`${algorithm} requires a valid PEM-encoded private key. Please paste your private key in the secret field.`, 'warning');
                    return;
                }
            } catch (keyError) {
                showStatus(`Invalid key format for ${algorithm}: ${keyError.message}`, 'error');
                return;
            }
        } else {
            showStatus(`Unsupported algorithm: ${algorithm}`, 'error');
            return;
        }

        // Update encoded JWT
        encodedJwtInput.value = token;
        encodedJwtInput.classList.add('valid');
        encodedJwtInput.classList.remove('invalid');
        
        showStatus('JWT encoded successfully!', 'success');
        
    } catch (error) {
        console.error('Encode error:', error);
        showStatus(`Encoding failed: ${error.message}`, 'error');
        encodedJwtInput.classList.remove('valid');
        encodedJwtInput.classList.add('invalid');
    }
}

// Verify JWT signature (optional verification)
async function verifyJWT() {
    try {
        const token = encodedJwtInput.value.trim();
        const algorithm = algorithmSelect.value;
        const secret = secretInput.value || defaultSecret;

        if (!token) {
            showStatus('No token to verify', 'warning');
            return;
        }

        if (algorithm.startsWith('HS')) {
            const secretKey = new TextEncoder().encode(secret);
            const { payload } = await jose.jwtVerify(token, secretKey);
            showStatus('Signature verified successfully!', 'success');
            return true;
        } else if (algorithm.startsWith('RS') || algorithm.startsWith('PS') || algorithm.startsWith('ES')) {
            if (secret.includes('BEGIN')) {
                // Determine if it's a public or private key
                const isPublicKey = secret.includes('PUBLIC KEY');
                let key;
                
                if (isPublicKey) {
                    key = await jose.importSPKI(secret, algorithm);
                } else {
                    key = await jose.importPKCS8(secret, algorithm);
                }
                
                const { payload } = await jose.jwtVerify(token, key);
                showStatus('Signature verified successfully!', 'success');
                return true;
            } else {
                showStatus('Public key required for verification', 'warning');
                return false;
            }
        }
    } catch (error) {
        console.error('Verification error:', error);
        showStatus(`Verification failed: ${error.message}`, 'warning');
        return false;
    }
}

// Auto-decode when JWT input changes
let decodeTimeout;
encodedJwtInput.addEventListener('input', () => {
    clearTimeout(decodeTimeout);
    decodeTimeout = setTimeout(() => {
        if (encodedJwtInput.value.trim()) {
            decodeJWT();
        } else {
            hideStatus();
            encodedJwtInput.classList.remove('valid', 'invalid');
        }
    }, 500);
});

// Update algorithm in header when selector changes
algorithmSelect.addEventListener('change', () => {
    try {
        const header = JSON.parse(headerJsonInput.value);
        header.alg = algorithmSelect.value;
        headerJsonInput.value = JSON.stringify(header, null, 2);
        
        // Show appropriate message for asymmetric algorithms
        const alg = algorithmSelect.value;
        if (alg.startsWith('RS') || alg.startsWith('PS') || alg.startsWith('ES')) {
            showStatus(`${alg} requires a PEM-encoded private key for signing and public key for verification`, 'warning');
        } else {
            hideStatus();
        }
    } catch (error) {
        console.error('Error updating algorithm:', error);
    }
});

// Button event listeners
encodeBtn.addEventListener('click', encodeJWT);
decodeBtn.addEventListener('click', decodeJWT);

// Auto-format JSON inputs
[headerJsonInput, payloadJsonInput].forEach(input => {
    input.addEventListener('blur', () => {
        try {
            const json = JSON.parse(input.value);
            input.value = JSON.stringify(json, null, 2);
        } catch (error) {
            // Invalid JSON, don't format
        }
    });
});

// Initialize on page load
initializeDefaults();
