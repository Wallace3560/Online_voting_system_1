/*
 * Overview: Global Menu
 * Purpose: Handles client-side interactions for this feature.
 */
(function () {
    if (document.getElementById('global-nav-fab')) {
        return;
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
        { href: 'results.php', label: 'Election Results' },
        { href: 'admin_login.php', label: 'Admin Login' },
        { href: 'voter_logout.php', label: 'Voter Logout' },
        { href: 'admin_logout.php', label: 'Admin Logout' }
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
    links.forEach(function (item) {
        if (current.endsWith('/' + item.href.toLowerCase()) || current === '/' + item.href.toLowerCase()) {
            return;
        }

        var anchor = document.createElement('a');
        anchor.className = 'global-nav-link';
        anchor.href = item.href;
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