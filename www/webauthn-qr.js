(async () => {
    const token = __TOKEN__;
    const action = __ACTION__;
    const base = location.pathname;
    const state = document.getElementById('state');
    const approve = document.getElementById('approve');
    const cancel = document.getElementById('cancel');
    const toBuffer = value => {
        value = value.replace(/-/g, '+').replace(/_/g, '/');
        while (value.length % 4) value += '=';
        const binary = atob(value);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    };
    const toBase64Url = value => {
        const bytes = new Uint8Array(value);
        let binary = '';
        for (const byte of bytes) binary += String.fromCharCode(byte);
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_')
            .replace(/=+$/, '');
    };
    const prepareOptions = options => {
        options.challenge = toBuffer(options.challenge);
        if (options.user) options.user.id = toBuffer(options.user.id);
        for (const name of ['allowCredentials', 'excludeCredentials']) {
            for (const credential of options[name] || []) {
                credential.id = toBuffer(credential.id);
            }
        }
        return options;
    };
    const credentialToJson = credential => {
        const response = credential.response;
        const data = {
            id: credential.id,
            rawId: toBase64Url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: toBase64Url(response.clientDataJSON),
            },
        };
        if (response.attestationObject) {
            data.response.attestationObject = toBase64Url(
                response.attestationObject);
        }
        if (response.authenticatorData) {
            data.response.authenticatorData = toBase64Url(
                response.authenticatorData);
            data.response.signature = toBase64Url(response.signature);
            if (response.userHandle) {
                data.response.userHandle = toBase64Url(response.userHandle);
            }
        }
        return data;
    };

    approve.onclick = async () => {
        approve.disabled = true;
        state.className = 'webauthn-state';
        state.textContent = __TEXT_WAITING__;
        try {
            if (!navigator.credentials
                    || typeof navigator.credentials[action] !== 'function') {
                throw Error(__TEXT_UNSUPPORTED__);
            }
            const optionsResponse = await fetch(`${base}/options`, {
                cache: 'no-store',
            });
            if (!optionsResponse.ok) throw Error(__TEXT_UNAVAILABLE__);
            const optionsData = await optionsResponse.json();
            const credential = await navigator.credentials[action]({
                publicKey: prepareOptions(optionsData.options),
            });
            const completeResponse = await fetch(`${base}/complete`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({credential: credentialToJson(credential)}),
            });
            if (!completeResponse.ok) throw Error(__TEXT_REJECTED__);
            state.textContent = __TEXT_APPROVED__;
            state.className = 'webauthn-state ok';
            cancel.disabled = true;
        } catch (error) {
            state.textContent = error.name === 'NotAllowedError'
                ? __TEXT_VERIFICATION_CANCELLED__ : (error.message
                    || __TEXT_UNAVAILABLE__);
            state.className = 'webauthn-state error';
            await fetch(`${base}/cancel`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({reason: 'rejected'}),
            });
        }
    };

    cancel.onclick = async () => {
        const response = await fetch(`${base}/cancel`, {method: 'POST'});
        if (response.ok) {
            state.textContent = __TEXT_CANCELLED__;
            state.className = 'webauthn-state error';
            approve.disabled = true;
            cancel.disabled = true;
        } else {
            state.textContent = __TEXT_CANCEL_FAILED__;
            state.className = 'webauthn-state error';
        }
    };
})();
