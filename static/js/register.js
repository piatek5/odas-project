
document.getElementById('registerForm')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const status = document.getElementById('status');
    const user = document.getElementById('username').value;
    const pass = document.getElementById('password').value;

    status.innerText = "Generowanie kluczy kryptograficznych...";

    try {
        const response = await Auth.register(user, pass);
        if (response.ok) {
            alert("Konto utworzone pomyślnie!");
            window.location.href = "/login";
        } else {
            throw new Error("Rejestracja nie powiodła się.");
        }
    } catch (err) {
        status.innerHTML = `<b style='color:red'>Błąd: ${err.message}</b>`;
    }
});