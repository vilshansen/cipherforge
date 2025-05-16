// Constants
const KEY_SIZE_BYTES = 32; // 256-bit key for AES-GCM
const TAG_SIZE_BYTES = 16; // Size of the authentication tag in AES-GCM
const NONCE_SIZE_BYTES = 12; // Size of the nonce (IV) in AES-GCM
const SALT_SIZE_BYTES = 16; // Size of the salt for PBKDF2 key derivation
const PBKDF2_ITERATIONS = 1000000; // Increased iterations for better security
const PASSWORD_LENGTH = 43; // Adjusted length for 256+ bits of entropy

// ASCII Armoring Tags
const START_TAG = "-----BEGIN AES-GCM ENCRYPTED DATA-----";
const END_TAG = "-----END AES-GCM ENCRYPTED DATA-----";

class CipherForge {
    static createSecurePassword(userProvided = null) {
        if (userProvided) {
            if (userProvided.length < 12) {
                console.warn("Warning: Password is short. Consider a longer password.");
            }
            return userProvided;
        }

        const array = new Uint8Array(PASSWORD_LENGTH);
        crypto.getRandomValues(array);
        const characterPool = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!#%&?.-"; // Expanded character pool
        return Array.from(array, byte => characterPool[byte % characterPool.length]).join('');
    }

    static async deriveKey(password, salt) {
        const encoder = new TextEncoder();
        const baseKey = await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );

        return await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: salt,
                iterations: PBKDF2_ITERATIONS,
                hash: "SHA-256",
            },
            baseKey,
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
    }

    static async encrypt(plaintext, userPassword = null) {
        if (!plaintext) throw new Error("Plaintext cannot be empty.");

        const password = this.createSecurePassword(userPassword);
        const salt = crypto.getRandomValues(new Uint8Array(SALT_SIZE_BYTES));
        const key = await this.deriveKey(password, salt);
        const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE_BYTES));

        const encoder = new TextEncoder();
        const encodedPlaintext = encoder.encode(plaintext);

        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv: nonce },
            key,
            encodedPlaintext
        );

        const encryptedData = new Uint8Array([...salt, ...nonce, ...new Uint8Array(ciphertext)]);
        const encryptedDataB64 = btoa(String.fromCharCode(...encryptedData));
        const asciiArmored = `${START_TAG}\n${encryptedDataB64}\n${END_TAG}`;

        return { asciiArmored, password };
    }

    static async decrypt(asciiArmored, password) {
        if (!asciiArmored || !password) throw new Error("Encrypted data and password cannot be empty.");

        const lines = asciiArmored.split("\n");
        const startIndex = lines.indexOf(START_TAG);
        const endIndex = lines.indexOf(END_TAG);

        if (startIndex === -1 || endIndex === -1) throw new Error("Invalid format: Start or end tag missing.");

        const encryptedDataB64 = lines.slice(startIndex + 1, endIndex).join("").trim();
        let encryptedData;
        try {
            encryptedData = new Uint8Array([...atob(encryptedDataB64)].map(char => char.charCodeAt(0)));
        } catch (e) {
            throw new Error("Invalid base64 data.");
        }

        const salt = encryptedData.slice(0, SALT_SIZE_BYTES);
        const nonce = encryptedData.slice(SALT_SIZE_BYTES, SALT_SIZE_BYTES + NONCE_SIZE_BYTES);
        const ciphertext = encryptedData.slice(SALT_SIZE_BYTES + NONCE_SIZE_BYTES);

        const key = await this.deriveKey(password, salt);
        let decryptedData;
        try {
            decryptedData = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: nonce },
                key,
                ciphertext
            );
        } catch (e) {
            throw new Error("Decryption failed. Incorrect password or corrupted data.");
        }

        return new TextDecoder().decode(decryptedData);
    }

	static async copyPassword() {
		const password = document.getElementById('password-display').textContent;
		await navigator.clipboard.writeText(password);
		document.getElementById('copy-message').style.display = 'block';
		setTimeout(() => {
			document.getElementById('copy-message').style.display = 'none';
		}, 2000);
	}

	static showLoading() {
		document.getElementById('loading').style.display = 'block';
		document.getElementById('progressBarContainer').style.display = 'block';
		document.getElementById('progressBar').style.width = '0%';
	}

	static hideLoading() {
		document.getElementById('loading').style.display = 'none';
		document.getElementById('progressBarContainer').style.display = 'none';
	}

	static updateProgress(progress) {
		document.getElementById('progressBar').style.width = `${progress}%`;
	}

	static async encryptText() {
		const inputText = document.getElementById('inputText').value.trim();
		if (!inputText) {
			alert('Please enter some text to encrypt.');
			return;
		}

		CipherForge.showLoading();
		let progress = 0;
		const intervalDuration = 30; // Adjust for speed
		const progressIncrement = 5;
		const progressInterval = setInterval(() => {
			progress += progressIncrement;
			CipherForge.updateProgress(Math.min(progress, 95)); // Cap at 95% to show completion after crypto
		}, intervalDuration);

		try {
			const { asciiArmored, password } = await CipherForge.encrypt(inputText);
			document.getElementById('outputText').value = asciiArmored;
			document.getElementById('password-display').textContent = password;
			document.getElementById('password-container').style.display = 'block';
			CipherForge.updateProgress(100);
		} catch (error) {
			console.error("Encryption error:", error);
			alert('Encryption failed: ' + error.message);
			CipherForge.updateProgress(0); // Reset progress on error
		} finally {
			clearInterval(progressInterval);
			setTimeout(CipherForge.hideLoading, 300); // Small delay to see 100%
		}
	}

	static async decryptText() {
		const inputText = document.getElementById('inputText').value.trim();
		if (!inputText) {
			alert('Please enter some text to decrypt.');
			return;
		}
		const password = prompt('Enter the password for decryption:').trim();
		if (!password) {
			alert('Password is required for decryption.');
			return;
		}

		CipherForge.showLoading();
		let progress = 0;
		const intervalDuration = 30; // Adjust for speed
		const progressIncrement = 5;
		const progressInterval = setInterval(() => {
			progress += progressIncrement;
			CipherForge.updateProgress(Math.min(progress, 95)); // Cap at 95%
		}, intervalDuration);

		try {
			const decryptedText = await CipherForge.decrypt(inputText, password);
			document.getElementById('outputText').value = decryptedText;
			document.getElementById('password-container').style.display = 'none';
			CipherForge.updateProgress(100);
		} catch (error) {
			console.error("Decryption error:", error);
			alert('Decryption failed: ' + error.message);
			CipherForge.updateProgress(0); // Reset progress on error
		} finally {
			clearInterval(progressInterval);
			setTimeout(CipherForge.hideLoading, 300); // Small delay to see 100%
		}
	}
}