# JWT Encoder/Decoder

A modern, Material Design-based web tool for encoding and decoding JSON Web Tokens (JWT). Built with HTML, CSS, and JavaScript using the [panva/jose](https://github.com/panva/jose) library.

🔗 **[Live Demo](https://adrienpessu.github.io/jwt-tools/)**

## Features

- 🔐 **Encode & Decode JWTs** - Convert between encoded tokens and their JSON representation
- 🎨 **Material Design UI** - Clean, modern interface following Material Design principles
- 🔧 **Multiple Algorithms** - Support for various JWT signing algorithms:
  - HMAC: HS256, HS384, HS512
  - RSA: RS256, RS384, RS512
  - ECDSA: ES256, ES384, ES512
  - RSA-PSS: PS256, PS384, PS512
- ✨ **Real-time Decoding** - Automatically decodes JWT as you type
- ✅ **Visual Feedback** - Clear indicators for valid/invalid tokens
- 📱 **Responsive Design** - Works on desktop, tablet, and mobile devices

## Usage

### Decoding a JWT

1. Paste your JWT token into the "Encoded JWT" text area
2. The tool will automatically decode and display:
   - Header (algorithm and token type)
   - Payload (claims and data)
3. Visual feedback will indicate if the token is valid or invalid

### Encoding a JWT

1. Edit the Header and Payload JSON in the right panel
2. Select your desired algorithm from the dropdown
3. Enter your secret key (or private key for asymmetric algorithms)
4. Click "Encode JWT" to generate the token
5. The encoded token will appear in the left panel

### Algorithm-Specific Notes

**HMAC Algorithms (HS256, HS384, HS512)**
- Use a shared secret string
- Same secret is used for both signing and verification

**RSA/ECDSA/RSA-PSS Algorithms (RS*, ES*, PS*)**
- Require PEM-encoded keys
- Use private key for signing
- Use public key for verification

## Technology Stack

- **HTML5** - Structure and semantics
- **CSS3** - Material Design styling
- **JavaScript (ES6+)** - Application logic
- **[panva/jose](https://github.com/panva/jose)** - JWT encoding/decoding library
- **GitHub Pages** - Hosting and deployment

## Local Development

1. Clone the repository:
   ```bash
   git clone https://github.com/adrienpessu/jwt-tools.git
   cd jwt-tools
   ```

2. Open `index.html` in your browser:
   ```bash
   # Using Python 3
   python -m http.server 8000
   
   # Or using Node.js
   npx http-server
   ```

3. Navigate to `http://localhost:8000` in your browser

## Deployment

This project is automatically deployed to GitHub Pages using GitHub Actions. Any push to the `main` branch will trigger a deployment.

### Manual Deployment

You can also manually trigger a deployment from the Actions tab in GitHub.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is open source and available under the MIT License.

## Acknowledgments

- Inspired by [jwt.io](https://jwt.io/)
- Built with [panva/jose](https://github.com/panva/jose)
- Material Design guidelines by Google