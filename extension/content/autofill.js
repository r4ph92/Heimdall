/**
 * Content script — injected into every page.
 * Detects login forms and fills them when instructed by the background service worker.
 * Runs in an isolated world so page JS cannot access this context.
 */

chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'fill') {
        fillForm(message.username, message.password);
    }
});

function fillForm(username, password) {
    const { usernameField, passwordField } = findLoginFields();

    if (usernameField && username) {
        setNativeValue(usernameField, username);
    }
    if (passwordField && password) {
        setNativeValue(passwordField, password);
        passwordField.focus();
    }
}

function findLoginFields() {
    const passwordFields = Array.from(
        document.querySelectorAll('input[type="password"]:not([disabled]):not([readonly])')
    ).filter(isVisible);

    if (passwordFields.length === 0) return {};

    const passwordField = passwordFields[0];

    // Walk backwards through the form to find the closest preceding text/email/tel input
    const form    = passwordField.closest('form') ?? document.body;
    const inputs  = Array.from(
        form.querySelectorAll('input[type="text"], input[type="email"], input[type="tel"], input:not([type])')
    ).filter(isVisible);

    // Pick the input that appears just before the password field in DOM order
    const allInputs = Array.from(form.querySelectorAll('input')).filter(isVisible);
    const pwIdx     = allInputs.indexOf(passwordField);
    const candidates = inputs.filter(i => allInputs.indexOf(i) < pwIdx);
    const usernameField = candidates.at(-1) ?? null;

    return { usernameField, passwordField };
}

function isVisible(el) {
    if (el.offsetParent === null) return false;
    const style = getComputedStyle(el);
    return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
}

/**
 * Triggers React/Vue/Angular change detection by using the native input value setter,
 * then dispatching input and change events.
 */
function setNativeValue(el, value) {
    const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype, 'value'
    )?.set;

    if (nativeInputValueSetter) {
        nativeInputValueSetter.call(el, value);
    } else {
        el.value = value;
    }

    el.dispatchEvent(new Event('input',  { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    el.dispatchEvent(new Event('blur',   { bubbles: true }));
}
