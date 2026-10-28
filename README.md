# 🔐 CipherLab

### A Multi-Cipher Encryption, Decryption & Encoding Toolkit for Kali Linux

<p align="center">
  <strong>One toolkit. Multiple ciphers. Endless cryptographic learning.</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-blue?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Linux" />
  <img src="https://img.shields.io/badge/Language-Python%203-yellow?style=for-the-badge&logo=python&logoColor=white" alt="Python 3" />
  <img src="https://img.shields.io/badge/Category-Cryptography-purple?style=for-the-badge" alt="Cryptography" />
  <img src="https://img.shields.io/badge/Status-Open%20Source-brightgreen?style=for-the-badge" alt="Open Source" />
</p>

---

## 🧩 Overview

**CipherLab** is a Python-based command-line cryptography toolkit designed for cybersecurity learners, students, and enthusiasts. It brings together classical cipher algorithms, common data encodings, brute-force experimentation, and modern authenticated encryption in one interactive tool.

Whether you're exploring historical cryptography, solving CTF challenges, learning how encodings differ from encryption, or experimenting with password-based encryption, CipherLab provides a convenient environment to practise.

## ✨ Features

### 🔏 Classical ciphers
- **Caesar Cipher** — shift-based encryption and decryption.
- **ROT13** — rotational letter substitution.
- **Atbash** — reversed-alphabet substitution.
- **Affine Cipher** — mathematical substitution cipher.
- **Vigenère Cipher** — keyword-based polyalphabetic cipher.
- **Rail Fence Cipher** — zigzag transposition.
- **Columnar Transposition** — column-based rearrangement.
- **Caesar brute force** — try possible shifts to help identify readable plaintext.

### 🔄 Encoding and decoding
- Base64
- Hexadecimal
- Binary representation
- URL encoding and decoding

> Encoding is not encryption. Encodings such as Base64 and hexadecimal do not provide confidentiality by themselves.

### 🛡️ Modern encryption
- **AES-256-GCM** authenticated encryption using a password.
- Password-based key derivation.
- Random salt and nonce generation.
- Authentication to detect tampering with encrypted data.

AES-GCM requires the Python `cryptography` package. Keep your encryption password safe: losing it may make the encrypted data unrecoverable.

### 🧰 Designed for learning
- Interactive terminal menu.
- Multiple cryptographic methods in one script.
- Built-in self-test option.
- Suitable for cryptography practice and educational experiments.

## 🖥️ Requirements

- Kali Linux or another compatible Linux distribution.
- Python 3.
- Terminal access.
- Python `cryptography` package for AES-256-GCM functionality.

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/codecanurag15/cipherlab.git
```

### 2. Enter the project directory

```bash
cd cipherlab
```

### 3. Install the AES-GCM dependency

On Kali Linux:

```bash
sudo apt update
sudo apt install python3-cryptography
```

Classical ciphers and the listed standard encodings use Python's standard library and do not require third-party packages.

### 4. Run CipherLab

```bash
python3 cipherlab.py
```

If you prefer to execute the script directly, you can make it executable:

```bash
chmod +x cipherlab.py
./cipherlab.py
```

## 🚀 Usage

Launch CipherLab:

```bash
python3 cipherlab.py
```

Follow the interactive menu to select an available operation. Depending on the selected method, enter the required plaintext, ciphertext, key, shift, or password.

### Example learning exercises

| Exercise | Objective |
|---|---|
| Caesar Cipher | Encrypt a message using a shift |
| ROT13 | Transform letters using a rotation of 13 |
| Vigenère | Explore keyword-based encryption |
| Base64 | Encode and decode text |
| Hexadecimal | Convert text to and from hexadecimal |
| Caesar brute force | Compare candidate plaintexts |
| AES-256-GCM | Encrypt and authenticate data using a password |

### Run the self-test

```bash
python3 cipherlab.py --self-test
```

Use this command to check the supported self-test routines. If the command or an operation behaves differently in your local copy, verify that your `cipherlab.py` matches the project version.

## 🔬 Educational use cases

- Learning classical cryptography fundamentals.
- Understanding the distinction between encoding and encryption.
- Practising introductory cryptography exercises.
- Exploring basic CTF-style cipher challenges.
- Experimenting with authenticated encryption.
- Studying why key selection, password handling, and authentication matter.

## ⚠️ Limitations and security notes

- Classical ciphers are intended for education and are **not secure for protecting sensitive information**.
- Caesar brute force works by testing possible shifts; it is not a universal ciphertext solver.
- CipherLab cannot guarantee successful decryption of an unknown ciphertext without knowing the algorithm, key, and expected format.
- AES-256-GCM is a modern authenticated-encryption algorithm, but the security of the overall implementation also depends on password strength, key derivation, nonce handling, and correct usage.
- Never commit passwords, secret keys, private data, or real sensitive ciphertexts to a public repository.

## 🗺️ Project structure

```text
cipherlab/
├── cipherlab.py
├── README.md
└── LICENSE
```

The repository may contain additional files depending on your current version.

## 🤝 Contributing

Contributions, bug reports, suggestions, and educational improvements are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Make your changes.
4. Test the functionality.
5. Open a pull request describing the changes.

Please test changes before submitting them, especially anything involving encryption, decryption, key handling, or input validation.

## 📜 License

This project is open source. Add a `LICENSE` file to the repository that reflects the license you choose, and update this section if necessary.

## 👨‍💻 Author

**Anurag Sharma**

GitHub: [@codecanurag15](https://github.com/codecanurag15)

---

<p align="center">
  <strong>🔐 CipherLab — Learn cryptography, one cipher at a time.</strong>
</p>

<p align="center">
  Built for cybersecurity education, experimentation, and cryptographic learning.
</p>
