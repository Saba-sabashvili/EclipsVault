// EclipsVault UI behaviours. CSP forbids inline scripts, so every interaction is
// wired here through data attributes:
//   form[data-confirm] / a[data-confirm]  → custom confirm dialog before proceeding
//   [data-copy="#selector"]               → copy target's text to the clipboard
//   [data-print]                          → print the current page (CSP forbids inline onclick)
//   [data-flash]                          → dismissible, auto-hiding toast
//   input[data-filter="#id"]              → live row filter for the referenced table
//   tr[data-href]                         → make a whole table row clickable
document.addEventListener('DOMContentLoaded', () => {
    wireConfirms();
    wireCopyButtons();
    wirePrintButtons();
    wireFlashes();
    wireTableFilters();
    wireRowLinks();
    wireAutoSubmit();
    wireMenus();
    wirePasskeys();
    wirePasswordBreachCheck();
    wireThemeToggle();
});

// --- Custom confirm dialog (replaces window.confirm for an Apple-style modal) ---
function confirmDialog(message) {
    return new Promise((resolve) => {
        const backdrop = document.createElement('div');
        backdrop.className = 'modal-backdrop';
        backdrop.innerHTML = `
            <div class="modal" role="alertdialog" aria-modal="true" aria-label="Please confirm">
                <h3>Please confirm</h3>
                <p></p>
                <div class="modal-actions">
                    <button type="button" class="button" data-cancel>Cancel</button>
                    <button type="button" class="button danger" data-ok>Continue</button>
                </div>
            </div>`;
        backdrop.querySelector('p').textContent = message;
        document.body.appendChild(backdrop);

        const close = (result) => {
            backdrop.remove();
            document.removeEventListener('keydown', onKey);
            resolve(result);
        };
        const onKey = (e) => {
            if (e.key === 'Escape') close(false);
            if (e.key === 'Enter') close(true);
        };

        backdrop.querySelector('[data-ok]').addEventListener('click', () => close(true));
        backdrop.querySelector('[data-cancel]').addEventListener('click', () => close(false));
        backdrop.addEventListener('click', (e) => { if (e.target === backdrop) close(false); });
        document.addEventListener('keydown', onKey);
        backdrop.querySelector('[data-ok]').focus();
    });
}

function wireConfirms() {
    // Forms: intercept submit.
    document.querySelectorAll('form[data-confirm]').forEach((form) => {
        form.addEventListener('submit', (event) => {
            if (form.dataset.confirmed === 'true') return;
            event.preventDefault();
            confirmDialog(form.dataset.confirm).then((ok) => {
                if (ok) { form.dataset.confirmed = 'true'; form.submit(); }
            });
        });
    });

    // Links (e.g. opening a honey-token decoy): intercept navigation.
    document.querySelectorAll('a[data-confirm]').forEach((link) => {
        link.addEventListener('click', (event) => {
            event.preventDefault();
            confirmDialog(link.dataset.confirm).then((ok) => {
                if (ok) window.location.href = link.href;
            });
        });
    });
}

function wireCopyButtons() {
    document.querySelectorAll('[data-copy]').forEach((button) => {
        button.addEventListener('click', async () => {
            const target = document.querySelector(button.dataset.copy);
            if (!target) return;
            try {
                await navigator.clipboard.writeText(target.textContent.trim());
                const original = button.textContent;
                button.textContent = 'Copied ✓';
                button.classList.add('copied');
                setTimeout(() => {
                    button.textContent = original;
                    button.classList.remove('copied');
                }, 1600);
            } catch {
                button.textContent = 'Copy failed';
            }
        });
    });
}

function wirePrintButtons() {
    document.querySelectorAll('[data-print]').forEach((button) => {
        button.addEventListener('click', () => window.print());
    });
}

function wireFlashes() {
    document.querySelectorAll('[data-flash]').forEach((flash) => {
        flash.querySelector('[data-flash-close]')?.addEventListener('click', () => flash.remove());
        setTimeout(() => {
            flash.classList.add('flash-hide');
            setTimeout(() => flash.remove(), 400);
        }, 6000);
    });
}

function wireTableFilters() {
    document.querySelectorAll('input[data-filter]').forEach((input) => {
        const table = document.querySelector(input.dataset.filter);
        if (!table) return;
        input.addEventListener('input', () => {
            const query = input.value.trim().toLowerCase();
            table.querySelectorAll('tbody tr').forEach((row) => {
                row.hidden = query !== '' && !row.textContent.toLowerCase().includes(query);
            });
        });
    });
}

function wireRowLinks() {
    document.querySelectorAll('tr[data-href]').forEach((row) => {
        row.addEventListener('click', (event) => {
            // Let real controls inside the row do their own thing.
            if (event.target.closest('a, button, form, input, details')) return;
            window.location.href = row.dataset.href;
        });
    });
}

// A form marked data-autosubmit submits as soon as the referenced input changes
// (used for the "Upload image" file picker so there is no separate submit button).
function wireAutoSubmit() {
    document.querySelectorAll('form[data-autosubmit]').forEach((form) => {
        const input = document.querySelector(form.dataset.autosubmit);
        input?.addEventListener('change', () => {
            if (input.value) form.submit();
        });
    });
}

// Close any open row overflow menu when clicking elsewhere.
function wireMenus() {
    document.addEventListener('click', (event) => {
        document.querySelectorAll('details.row-menu[open]').forEach((menu) => {
            if (!menu.contains(event.target)) menu.removeAttribute('open');
        });
    });
}

// --- Theme toggle ----------------------------------------------------------------
// The server stamps <html data-theme> from the EclipsVault.Theme cookie so the first
// paint is already correct (no flash). Clicking the toggle flips it live and rewrites
// the cookie so the choice sticks on the next load.
function wireThemeToggle() {
    document.querySelectorAll('[data-theme-toggle]').forEach((button) => {
        button.addEventListener('click', () => {
            const next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', next);
            document.cookie = `EclipsVault.Theme=${next}; path=/; max-age=31536000; SameSite=Strict; Secure`;
        });
    });
}

// --- WebAuthn / passkeys ---------------------------------------------------------
// [data-passkey-register] registers a new authenticator for the signed-in user;
// [data-passkey-login] performs a passwordless sign-in. Both talk to the server over
// fetch(), converting the base64url fields the JSON API uses to/from the ArrayBuffers
// the WebAuthn browser API expects.
function wirePasskeys() {
    const registerButton = document.querySelector('[data-passkey-register]');
    const loginButton = document.querySelector('[data-passkey-login]');

    if (registerButton) {
        if (!window.PublicKeyCredential) return disablePasskeyUi(registerButton);
        registerButton.addEventListener('click', () => registerPasskey(registerButton));
    }
    if (loginButton) {
        if (!window.PublicKeyCredential) return disablePasskeyUi(loginButton);
        loginButton.addEventListener('click', () => loginWithPasskey(loginButton));
    }
}

async function registerPasskey(button) {
    const status = document.querySelector('[data-passkey-status]');
    const nickname = document.querySelector(button.dataset.nickname || '#passkey-nickname');
    try {
        setPasskeyStatus(status, 'Follow the prompt on your device…', false);
        button.disabled = true;

        const options = await passkeyPost('/Profile/PasskeyRegisterBegin').then(readJson);
        options.challenge = base64urlToBuffer(options.challenge);
        options.user.id = base64urlToBuffer(options.user.id);
        options.excludeCredentials = (options.excludeCredentials || []).map(withBufferId);

        const credential = await navigator.credentials.create({ publicKey: options });
        const result = await passkeyPost('/Profile/PasskeyRegisterComplete', {
            nickname: nickname ? nickname.value : '',
            credential: {
                id: credential.id,
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                attestationObject: bufferToBase64url(credential.response.attestationObject)
            }
        }).then(readJson);

        if (result.success) {
            window.location.reload();
        } else {
            setPasskeyStatus(status, result.error || 'Registration failed.', true);
            button.disabled = false;
        }
    } catch (err) {
        setPasskeyStatus(status, friendlyPasskeyError(err), true);
        button.disabled = false;
    }
}

async function loginWithPasskey(button) {
    const status = document.querySelector('[data-passkey-status]');
    const usernameInput = button.dataset.username ? document.querySelector(button.dataset.username) : null;
    try {
        setPasskeyStatus(status, 'Follow the prompt on your device…', false);
        button.disabled = true;

        const options = await passkeyPost('/Account/PasskeyLoginBegin', {
            username: usernameInput ? usernameInput.value : null
        }).then(readJson);
        options.challenge = base64urlToBuffer(options.challenge);
        options.allowCredentials = (options.allowCredentials || []).map(withBufferId);

        const assertion = await navigator.credentials.get({ publicKey: options });
        const result = await passkeyPost('/Account/PasskeyLoginComplete', {
            credential: {
                id: assertion.id,
                clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                signature: bufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null
            }
        }).then(readJson);

        if (result.success) {
            window.location.href = result.redirect || '/';
        } else {
            setPasskeyStatus(status, result.error || 'Sign-in failed.', true);
            button.disabled = false;
        }
    } catch (err) {
        setPasskeyStatus(status, friendlyPasskeyError(err), true);
        button.disabled = false;
    }
}

// --- Live breached-password check ------------------------------------------------
// An input marked data-breach-check="<url>" is screened (debounced) against the
// compromised-password corpus once it reaches the minimum length; the verdict is shown
// in the element named by data-breach-status.
function wirePasswordBreachCheck() {
    document.querySelectorAll('input[data-breach-check]').forEach((input) => {
        const url = input.dataset.breachCheck;
        const status = document.querySelector(input.dataset.breachStatus);
        let timer;
        let seq = 0;
        input.addEventListener('input', () => {
            clearTimeout(timer);
            const value = input.value;
            if (value.length < 12) {
                setBreachStatus(status, '', false);
                return;
            }
            timer = setTimeout(async () => {
                const mine = ++seq;
                try {
                    const token = document.querySelector('input[name="__RequestVerificationToken"]');
                    const res = await fetch(url, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json', 'RequestVerificationToken': token ? token.value : '' },
                        body: JSON.stringify({ password: value })
                    });
                    if (!res.ok || mine !== seq) return;
                    const data = await res.json();
                    if (mine !== seq) return; // a newer keystroke already superseded this
                    setBreachStatus(status, data.compromised
                        ? '⚠ This password has appeared in known data breaches — choose a different one.'
                        : '✓ Not found in the breach corpus.', data.compromised);
                } catch {
                    // Network hiccup: stay silent; the server still screens on submit.
                }
            }, 400);
        });
    });
}

function setBreachStatus(el, message, isWarn) {
    if (!el) return;
    el.textContent = message;
    el.classList.toggle('status-error', !!isWarn);
    el.classList.toggle('status-ok', !isWarn && message !== '');
}

function passkeyPost(url, body) {
    const token = document.querySelector('input[name="__RequestVerificationToken"]');
    return fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'RequestVerificationToken': token ? token.value : ''
        },
        body: body === undefined ? undefined : JSON.stringify(body)
    });
}

async function readJson(response) {
    if (!response.ok) throw new Error('The server rejected the request.');
    return response.json();
}

function withBufferId(descriptor) {
    return Object.assign({}, descriptor, { id: base64urlToBuffer(descriptor.id) });
}

function setPasskeyStatus(el, message, isError) {
    if (!el) return;
    el.textContent = message;
    el.classList.toggle('status-error', isError);
    el.classList.toggle('status-ok', !isError && message !== '');
}

function disablePasskeyUi(button) {
    button.disabled = true;
    button.title = 'This browser does not support passkeys.';
}

function friendlyPasskeyError(err) {
    if (err && (err.name === 'NotAllowedError' || err.name === 'AbortError')) {
        return 'The passkey prompt was dismissed or timed out.';
    }
    return (err && err.message) || 'Something went wrong with the passkey.';
}

function base64urlToBuffer(value) {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '==='.slice((base64.length + 3) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

function bufferToBase64url(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
