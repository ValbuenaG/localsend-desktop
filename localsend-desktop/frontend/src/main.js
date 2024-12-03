import './style.css';
import { GetLocalIPs, StartServer, GetCurrentPIN, RegisterWithDevice, SendTestFile } from '../wailsjs/go/main/App';

document.querySelector('#app').innerHTML = `
    <div class="container">
        <h1>LocalSend Desktop</h1>
        <div class="card">
            <button id="start-server" type="button">Start Server</button>
            <div id="ip-list"></div>
            <div id="pin-display"></div>

            <div class="connection-controls">
                <h3>Connect to iOS Device</h3>
                <input type="text" id="ios-ip" placeholder="iOS IP Address" />
                <input type="text" id="ios-port" placeholder="iOS Port (e.g., 53318)" value="53318" />
                <input type="text" id="ios-pin" placeholder="iOS PIN" />
                <button id="register-button">Register</button>
                <button id="send-file-button">Send Test File</button>
                <div id="status-message"></div>
            </div>
        </div>
    </div>
`;

// Get and display local IPs
async function displayLocalIPs() {
    try {
        const ips = await GetLocalIPs();
        const pin = await GetCurrentPIN();

        const ipList = document.getElementById('ip-list');
        const pinDisplay = document.getElementById('pin-display');

        ipList.innerHTML = `
            <h3>Local IP Addresses:</h3>
            <ul>
                ${ips.map(ip => `<li>${ip}</li>`).join('')}
            </ul>
        `;

        pinDisplay.innerHTML = `
            <h3>Connection PIN:</h3>
            <div class="pin">${pin}</div>
        `;
    } catch (error) {
        console.error('Failed to get local IPs:', error);
    }
}

// Start server on button click
document.getElementById('start-server').addEventListener('click', async () => {
    try {
        await StartServer(53317);
        document.getElementById('start-server').textContent = 'Server Running on Port 53317';
        document.getElementById('start-server').disabled = true;
    } catch (error) {
        console.error('Failed to start server:', error);
    }
});

// Add event listeners for the new buttons
document.getElementById('register-button').addEventListener('click', async () => {
    const ip = document.getElementById('ios-ip').value;
    const port = parseInt(document.getElementById('ios-port').value);
    const statusMessage = document.getElementById('status-message');

    try {
        await RegisterWithDevice(ip, port);
        statusMessage.textContent = 'Successfully registered with iOS device';
        statusMessage.style.color = 'green';
    } catch (error) {
        statusMessage.textContent = `Failed to register: ${error}`;
        statusMessage.style.color = 'red';
    }
});

document.getElementById('send-file-button').addEventListener('click', async () => {
    const ip = document.getElementById('ios-ip').value;
    const port = parseInt(document.getElementById('ios-port').value);
    const pin = document.getElementById('ios-pin').value;
    const statusMessage = document.getElementById('status-message');

    try {
        await SendTestFile(ip, port, pin);
        statusMessage.textContent = 'File sent successfully';
        statusMessage.style.color = 'green';
    } catch (error) {
        statusMessage.textContent = `Failed to send file: ${error}`;
        statusMessage.style.color = 'red';
    }
});
// Display IPs when the page loads
displayLocalIPs();