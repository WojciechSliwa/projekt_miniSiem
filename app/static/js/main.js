import { initDashboard } from './dashboard.js';
import { initAdmin } from './admin.js';

function main() {
    const path = window.location.pathname;

    if (path === '/' || path === '/index') {
        console.log("Inicjalizacja Dashboardu");
        initDashboard();
    } 
    else if (path === '/config') {
        console.log("Inicjalizacja Panelu Admina");
        initAdmin();
    }
}

main();