(function () {
    const menuToggle = document.getElementById('menu-toggle');
    const sidebar = document.getElementById('admin-sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    function toggleSidebar() {
        sidebar?.classList.toggle('active');
        overlay?.classList.toggle('active');
    }
    menuToggle?.addEventListener('click', toggleSidebar);
    overlay?.addEventListener('click', toggleSidebar);
    document.querySelectorAll('form').forEach((form) => {
        form.addEventListener('submit', function (event) {
            if (form.dataset.submitted) {
                event.preventDefault();
                return;
            }
            form.dataset.submitted = '1';
        });
    });
}());
