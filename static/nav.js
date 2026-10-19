/*
 * Small-screen navigation: a Menu button that shows and hides the page nav.
 *
 * Drop-in: a page with a <nav> only needs <script src="/nav.js"></script>.
 * The button goes into the brand row and is hidden by rustguac.css above the
 * small-screen breakpoint, so desktop layouts are untouched. The nav is only
 * collapsed once this script has marked it (.nav-collapsible), so a page that
 * fails to load the script still shows its links.
 */
(function () {
    'use strict';
    if (window.__rgNavToggle) return;
    window.__rgNavToggle = true;

    function init() {
        var nav = document.querySelector('body > nav');
        var brand = document.querySelector('.brand-row');
        if (!nav || !brand) return;
        if (!nav.id) nav.id = 'site-nav';
        nav.setAttribute('aria-label', 'Main');

        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'nav-toggle';
        btn.setAttribute('aria-controls', nav.id);
        btn.setAttribute('aria-expanded', 'false');
        btn.innerHTML = '<span class="nav-toggle-icon" aria-hidden="true">&#9776;</span> Menu';
        brand.appendChild(btn);
        nav.classList.add('nav-collapsible');

        function setOpen(open) {
            nav.classList.toggle('nav-open', open);
            btn.setAttribute('aria-expanded', open ? 'true' : 'false');
        }
        btn.addEventListener('click', function () {
            setOpen(!nav.classList.contains('nav-open'));
        });
        // A link that stays on the page (Credentials on Connections, Logout)
        // should not leave the menu covering what it opened.
        nav.addEventListener('click', function (e) {
            if (e.target.closest('a')) setOpen(false);
        });
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && nav.classList.contains('nav-open')) {
                setOpen(false);
                btn.focus();
            }
        });
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
