
document.getElementById('loginForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const status = document.getElementById('loginStatus');
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;

    status.innerText = "Trwa odszyfrowywanie kluczy...";

    try {
        await Auth.login(user, pass);
        window.location.href = "/dashboard";
    } catch (err) {
        status.innerHTML = `<b style='color:red'>Błąd: ${err.message}</b>`;
    }
});