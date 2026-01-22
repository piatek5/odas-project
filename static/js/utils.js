
// Konwersja binarnych danych na Base64
const arrayBufferToBase64 = buffer => btoa(String.fromCharCode(...new Uint8Array(buffer)));

// Konwersja Base64 na ArrayBuffer
const base64ToArrayBuffer = base64 => {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
};

// Pomocnik do czytania plików
const fileToBase64 = file => new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.readAsDataURL(file);
    reader.onload = () => resolve(reader.result);
    reader.onerror = error => reject(error);
});