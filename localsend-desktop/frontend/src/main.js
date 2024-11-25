import './style.css';
import { GetLocalIPs, StartServer } from '../wailsjs/go/main/App';

document.querySelector('#app').innerHTML = `
    <div class="container">
        <h1>LocalSend Desktop</h1>
        <div class="card">
            <button id="start-server" type="button">Start Server</button>
            <div id="ip-list"></div>
        </div>
    </div>
`;

// Get and display local IPs
async function displayLocalIPs() {
    try {
        const ips = await GetLocalIPs();
        const ipList = document.getElementById('ip-list');
        ipList.innerHTML = `
            <h3>Local IP Addresses:</h3>
            <ul>
                ${ips.map(ip => `<li>${ip}</li>`).join('')}
            </ul>
        `;
    } catch (error) {
        console.error('Failed to get local IPs:', error);
    }
}

// Start server on button click
document.getElementById('start-server').addEventListener('click', async () => {
    try {
        await StartServer(8080);
        document.getElementById('start-server').textContent = 'Server Running on Port 8080';
        document.getElementById('start-server').disabled = true;
    } catch (error) {
        console.error('Failed to start server:', error);
    }
});

// Display IPs when the page loads
displayLocalIPs();