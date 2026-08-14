/*
 * Overview: Global Menu
 * Purpose: Handles client-side interactions for this feature.
 */
(function () {
    var adminNonceParam = 'admin_tab_nonce';
    var adminNonceStorageKey = 'ovs_admin_tab_nonce';
    var pathname = (window.location.pathname || '').toLowerCase();
    var adminProtectedPages = [
        '/admin_verify_voters.php',
        '/sub_admin_dashboard.php',
        '/election_officer_dashboard.php',
        '/admin_records.php',
        '/admin_manage_voters.php',
        '/admin_candidate_change_history.php'
    ];

    function isAdminProtectedPath(path) {
        for (var i = 0; i < adminProtectedPages.length; i++) {
            if (path.endsWith(adminProtectedPages[i])) {
                return true;
            }
        }
        return false;
    }

    function getQueryParam(name) {
        var params = new URLSearchParams(window.location.search || '');
        return params.get(name) || '';
    }

    function addOrReplaceQueryParam(urlString, name, value) {
        try {
            var resolved = new URL(urlString, window.location.origin);
            resolved.searchParams.set(name, value);
            return resolved.toString();
        } catch (e) {
            return urlString;
        }
    }

    function normalizeLocalHref(resolvedUrl) {
        if (!resolvedUrl || resolvedUrl.origin !== window.location.origin) {
            return resolvedUrl ? resolvedUrl.href : '';
        }
        return resolvedUrl.pathname + resolvedUrl.search + resolvedUrl.hash;
    }

    function ensureAdminTabNonceBindings() {
        if (!isAdminProtectedPath(pathname)) {
            return;
        }

        var requestNonce = getQueryParam(adminNonceParam);
        if (requestNonce) {
            try {
                sessionStorage.setItem(adminNonceStorageKey, requestNonce);
            } catch (e) {
                return;
            }

            try {
                var cleanUrl = new URL(window.location.href);
                cleanUrl.searchParams.delete(adminNonceParam);
                window.history.replaceState({}, document.title, cleanUrl.pathname + cleanUrl.search + cleanUrl.hash);
            } catch (e) {
                // no-op
            }
        }

        var storedNonce = '';
        try {
            storedNonce = sessionStorage.getItem(adminNonceStorageKey) || '';
        } catch (e) {
            storedNonce = '';
        }

        if (!storedNonce) {
            return;
        }

        var anchors = document.querySelectorAll('a[href]');
        for (var i = 0; i < anchors.length; i++) {
            var href = anchors[i].getAttribute('href') || '';
            if (!href || href.indexOf('#') === 0 || href.toLowerCase().indexOf('javascript:') === 0) {
                continue;
            }

            var resolved;
            try {
                resolved = new URL(href, window.location.origin);
            } catch (e) {
                continue;
            }

            if (resolved.origin !== window.location.origin) {
                continue;
            }

            if (!resolved.pathname.toLowerCase().endsWith('.php')) {
                continue;
            }

            resolved.searchParams.set(adminNonceParam, storedNonce);
            anchors[i].setAttribute('href', normalizeLocalHref(resolved));
        }

        var forms = document.querySelectorAll('form');
        for (var j = 0; j < forms.length; j++) {
            var form = forms[j];
            var hidden = form.querySelector('input[name="' + adminNonceParam + '"]');
            if (!hidden) {
                hidden = document.createElement('input');
                hidden.type = 'hidden';
                hidden.name = adminNonceParam;
                form.appendChild(hidden);
            }
            hidden.value = storedNonce;
        }
    }

    ensureAdminTabNonceBindings();

    if (document.getElementById('global-nav-fab')) {
        return;
    }

    if (!document.getElementById('iebc-flag-heading')) {
        var headingWrap = document.createElement('div');
        headingWrap.id = 'iebc-flag-heading';
        headingWrap.className = 'iebc-flag-heading';

        var heading = document.createElement('h1');
        heading.className = 'iebc-flag-heading-text';

        var wordIndependent = document.createElement('span');
        wordIndependent.className = 'iebc-word-independent';
        wordIndependent.textContent = 'INDEPENDENT';

        var wordMiddle = document.createElement('span');
        wordMiddle.className = 'iebc-word-electoral-boundaries';
        wordMiddle.textContent = 'ELECTORAL AND BOUNDARIES';

        var wordCommission = document.createElement('span');
        wordCommission.className = 'iebc-word-commission';
        wordCommission.textContent = 'COMMISSION';

        heading.appendChild(wordIndependent);
        heading.appendChild(document.createTextNode(' '));
        heading.appendChild(wordMiddle);
        heading.appendChild(document.createTextNode(' '));
        heading.appendChild(wordCommission);

        headingWrap.appendChild(heading);
        document.body.insertBefore(headingWrap, document.body.firstChild);
    }

    var roleHome = 'index.html';
    if (window.__ROLE_HOME__ && typeof window.__ROLE_HOME__ === 'string' && window.__ROLE_HOME__.trim() !== '') {
        roleHome = window.__ROLE_HOME__.trim();
    }

    var links = [
        { href: roleHome, label: 'Role Home' },
        { href: 'index.html', label: 'Home' },
        { href: 'login.php', label: 'Voter Login' },
        { href: 'register.php', label: 'Register Voter' },
        { href: 'check_verification.php', label: 'Check Verification' },
        { href: 'resend_verification.php', label: 'Resend Verification Email' },
        { href: 'forgot_password.php', label: 'Forgot Password' },
        { href: 'ballot.php', label: 'Ballot' },
        { href: 'voter_account.php', label: 'My Account' },
        { href: 'change_location.php', label: 'Change Location' },
        { href: 'results.php', label: 'Election Results' },
        { href: 'admin_login.php', label: 'Admin Login' },
        { href: 'voter_logout.php', label: 'Voter Logout' }
    ];

    var panel = document.createElement('div');
    panel.id = 'global-nav-panel';
    panel.className = 'global-nav-panel';
    panel.hidden = true;

    var title = document.createElement('div');
    title.className = 'global-nav-title';
    title.textContent = 'Quick Navigation';
    panel.appendChild(title);

    var list = document.createElement('div');
    list.className = 'global-nav-list';

    var current = (window.location.pathname || '').toLowerCase();
    var navNonce = '';
    try {
        navNonce = sessionStorage.getItem(adminNonceStorageKey) || '';
    } catch (e) {
        navNonce = '';
    }

    links.forEach(function (item) {
        if (current.endsWith('/' + item.href.toLowerCase()) || current === '/' + item.href.toLowerCase()) {
            return;
        }

        var anchor = document.createElement('a');
        anchor.className = 'global-nav-link';
        if (navNonce && isAdminProtectedPath(pathname)) {
            anchor.href = addOrReplaceQueryParam(item.href, adminNonceParam, navNonce);
        } else {
            anchor.href = item.href;
        }
        anchor.textContent = item.label;
        list.appendChild(anchor);
    });

    panel.appendChild(list);

    var menuButton = document.createElement('button');
    menuButton.id = 'global-nav-fab';
    menuButton.type = 'button';
    menuButton.className = 'global-nav-fab';
    menuButton.textContent = 'Menu';
    menuButton.setAttribute('aria-expanded', 'false');

    var homeButton = document.createElement('button');
    homeButton.type = 'button';
    homeButton.className = 'global-nav-home';
    homeButton.textContent = 'Role Home';
    homeButton.addEventListener('click', function () {
        if (navNonce && isAdminProtectedPath(pathname)) {
            window.location.href = addOrReplaceQueryParam(roleHome, adminNonceParam, navNonce);
            return;
        }
        window.location.href = roleHome;
    });

    menuButton.addEventListener('click', function () {
        panel.hidden = !panel.hidden;
        menuButton.setAttribute('aria-expanded', panel.hidden ? 'false' : 'true');
    });

    document.addEventListener('click', function (event) {
        if (panel.hidden) {
            return;
        }

        if (event.target === menuButton || panel.contains(event.target)) {
            return;
        }

        panel.hidden = true;
        menuButton.setAttribute('aria-expanded', 'false');
    });

    document.body.appendChild(panel);
    document.body.appendChild(homeButton);
    document.body.appendChild(menuButton);
})();