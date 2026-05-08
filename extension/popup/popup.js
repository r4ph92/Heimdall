// Popup controller — all sensitive operations go through the background service worker.

const bg = msg => chrome.runtime.sendMessage(msg);

// ─── DOM references ────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

const views = {
    login:     $('view-login'),
    biometric: $('view-biometric'),
    vault:     $('view-vault'),
};

const spinner          = $('spinner');
const btnLogout        = $('btn-logout');
const loginError       = $('login-error');
const biometricError   = $('biometric-error');

// ─── State ─────────────────────────────────────────────────────────────────────
let currentDomain = null;
let allEntries    = [];

// ─── Init ──────────────────────────────────────────────────────────────────────
(async () => {
    setLoading(true);

    // Detect current tab's domain for entry matching
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.url) {
        try { currentDomain = new URL(tab.url).hostname; } catch {}
    }

    const state = await bg({ type: 'getState' });

    if (state.unlocked) {
        await loadVaultView();
    } else if (state.hasBiometric) {
        showView('biometric');
    } else {
        showView('login');
    }

    setLoading(false);
})();

// ─── View transitions ──────────────────────────────────────────────────────────
function showView(name) {
    Object.entries(views).forEach(([k, el]) => el.hidden = k !== name);
    btnLogout.hidden = name !== 'vault';
}

function setLoading(on) {
    spinner.hidden = !on;
    if (on) Object.values(views).forEach(v => v.hidden = true);
}

// ─── Login ─────────────────────────────────────────────────────────────────────
$('btn-login').addEventListener('click', async () => {
    const email    = $('email').value.trim();
    const password = $('password').value;

    if (!email || !password) { showError(loginError, 'Email and password required.'); return; }

    hideError(loginError);
    setLoading(true);

    const res = await bg({ type: 'login', email, password });

    setLoading(false);

    if (res?.error) {
        showError(loginError, res.error);
        showView('login');
    } else {
        await loadVaultView();
    }
});

$('password').addEventListener('keydown', e => {
    if (e.key === 'Enter') $('btn-login').click();
});

// ─── Biometric unlock ──────────────────────────────────────────────────────────
$('btn-biometric').addEventListener('click', async () => {
    hideError(biometricError);
    setLoading(true);

    const res = await bg({ type: 'biometricUnlock' });

    setLoading(false);

    if (res?.error) {
        showError(biometricError, res.error);
        showView('biometric');
    } else {
        await loadVaultView();
    }
});

$('btn-use-password').addEventListener('click', () => {
    hideError(biometricError);
    showView('login');
});

// ─── Vault view ────────────────────────────────────────────────────────────────
async function loadVaultView() {
    const res = await bg({ type: 'getEntries', domain: currentDomain });

    if (res.locked) { showView('biometric'); return; }

    allEntries = res.entries ?? [];
    renderEntries(allEntries);

    // Domain badge
    const badge = $('domain-badge');
    if (currentDomain) {
        badge.textContent = currentDomain;
        badge.hidden      = false;
    }

    // Biometric button visibility
    const state = await bg({ type: 'getState' });
    $('btn-setup-biometric').hidden   = state.hasBiometric;
    $('btn-forget-biometric').hidden  = !state.hasBiometric;

    showView('vault');
}

function renderEntries(entries) {
    const list     = $('entry-list');
    const emptyMsg = $('empty-msg');

    list.innerHTML = '';

    if (entries.length === 0) {
        emptyMsg.hidden = false;
        return;
    }

    emptyMsg.hidden = true;

    entries.forEach(entry => {
        const li = document.createElement('li');
        li.className = 'entry-item';

        const initial = (entry.service_name?.[0] ?? '?').toUpperCase();

        li.innerHTML = `
            <div class="entry-favicon">${initial}</div>
            <div class="entry-meta">
                <div class="entry-service">${esc(entry.service_name)}</div>
                <div class="entry-username">${esc(entry.username ?? '')}</div>
            </div>
            <button class="btn-fill" data-id="${entry.id}">Fill</button>
        `;

        li.querySelector('.btn-fill').addEventListener('click', async e => {
            e.stopPropagation();
            const res = await bg({ type: 'fillCredentials', entryId: entry.id });
            if (res?.error) alert(res.error);
            else window.close();
        });

        list.appendChild(li);
    });
}

// ─── Search ────────────────────────────────────────────────────────────────────
$('search').addEventListener('input', e => {
    const q = e.target.value.toLowerCase().trim();
    if (!q) { renderEntries(allEntries); return; }
    renderEntries(allEntries.filter(entry =>
        entry.service_name?.toLowerCase().includes(q) ||
        entry.username?.toLowerCase().includes(q)
    ));
});

// ─── Biometric setup ───────────────────────────────────────────────────────────
$('btn-setup-biometric').addEventListener('click', async () => {
    setLoading(true);
    const res = await bg({ type: 'setupBiometric' });
    setLoading(false);

    if (res?.error) {
        alert('Biometric setup failed: ' + res.error);
    } else {
        $('btn-setup-biometric').hidden  = true;
        $('btn-forget-biometric').hidden = false;
    }
    showView('vault');
});

$('btn-forget-biometric').addEventListener('click', async () => {
    if (!confirm('Remove saved biometrics? You will need your master password next time.')) return;
    await bg({ type: 'forgetBiometric' });
    $('btn-setup-biometric').hidden  = false;
    $('btn-forget-biometric').hidden = true;
});

// ─── Logout ────────────────────────────────────────────────────────────────────
btnLogout.addEventListener('click', async () => {
    await bg({ type: 'logout' });
    showView('login');
});

// ─── Helpers ───────────────────────────────────────────────────────────────────
function showError(el, msg) { el.textContent = msg; el.hidden = false; }
function hideError(el)       { el.hidden = true; }

function esc(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}
