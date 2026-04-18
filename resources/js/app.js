import './bootstrap';

// Global confirm modal store — used by all custom confirmation dialogs
document.addEventListener('alpine:init', () => {
    Alpine.store('modal', {
        open: false,
        message: '',
        confirmLabel: 'Confirm',
        isDanger: true,
        _resolve: null,

        confirm(message, onConfirm, { confirmLabel = 'Confirm', isDanger = true } = {}) {
            this.message      = message;
            this.confirmLabel = confirmLabel;
            this.isDanger     = isDanger;
            this.open         = true;
            this._resolve     = onConfirm;
        },

        accept() {
            this.open = false;
            if (this._resolve) this._resolve();
            this._resolve = null;
        },

        cancel() {
            this.open     = false;
            this._resolve = null;
        },
    });

    Alpine.store('theme', {
        dark: localStorage.getItem('theme') !== 'light',

        toggle() {
            this.dark = !this.dark;
            localStorage.setItem('theme', this.dark ? 'dark' : 'light');
            document.documentElement.classList.toggle('dark', this.dark);
        },
    });
});
