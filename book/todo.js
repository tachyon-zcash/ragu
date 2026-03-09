// Reads todo path data injected by preprocessor-todo.py and adds badge
// elements to matching sidebar links, styled by custom.css. Also adds an
// admonish warning banner at the top of the current page if it is a todo page.
(function () {
    var el = document.querySelector('script.todo-data');
    if (!el) return;
    var paths = JSON.parse(el.textContent);

    // Resolve todo paths to absolute hrefs using mdBook's path_to_root,
    // so matching works regardless of where the book is hosted.
    var root = (typeof path_to_root !== 'undefined') ? path_to_root : '';

    // Sidebar badges
    paths.forEach(function (path) {
        var resolved = root + path;
        document.querySelectorAll('ol.chapter a[href="' + resolved + '"]')
            .forEach(function (a) {
                if (!a.querySelector('.todo-badge')) {
                    var span = document.createElement('span');
                    span.className = 'todo-badge';
                    a.appendChild(span);
                }
            });
    });

    // Page banner: check if the current page is a todo page via the active
    // sidebar link, which mdBook marks with the "active" class.
    var active = document.querySelector('ol.chapter a.active');
    if (active && active.querySelector('.todo-badge')) {
        var h1 = document.querySelector('main h1');
        if (h1) {
            var banner = document.createElement('div');
            banner.className = 'admonition admonish-warning';
            banner.innerHTML =
                '<p class="admonition-title" style="border-color: inherit">' +
                'Under Development' +
                '</p>' +
                '<p>This section is under development and may not be consistent ' +
                'with the current code. It may contain errors and inaccuracies.</p>';
            h1.parentNode.insertBefore(banner, h1.nextSibling);
        }
    }
})();
