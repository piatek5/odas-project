
document.getElementById('loginForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const status = document.getElementById('loginStatus');
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;

    status.innerText = "Trwa odszyfrowywanie kluczy...";

    try {
        // Pierwsza próba logowania
        let result = await Auth.login(user, pass);

        // Jeśli wymagany jest kod 2FA, pytamy o niego użytkownika
        if (result.status === "2fa_required") {
            const totpCode = prompt("Wprowadź 6-cyfrowy kod z aplikacji Google Authenticator:");
            if (!totpCode) return;

            // Ponowna próba logowania, tym razem z kodem
            result = await Auth.login(user, pass, totpCode);
        }

        if (result.status === "ok") {
            window.location.href = "/dashboard";
        }
    } catch (err) {
        status.innerHTML = `<b style='color:red'>Błąd: ${err.message}</b>`;
    }
});