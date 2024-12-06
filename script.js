import * as oauth from './openid-client-6.1.7.js';

//const CLIENT_ID = '23PZBH';
//const REDIRECT_URI = 'http://localhost:8083/';
const CLIENT_ID = '23PZVW';
const REDIRECT_URI = 'https://jvns-fitbit-graph.netlify.app/';

const as = {
    issuer: 'https://www.fitbit.com',
    authorization_endpoint: 'https://www.fitbit.com/oauth2/authorize',
    token_endpoint: 'https://api.fitbit.com/oauth2/token'
};

const config = new oauth.Configuration(as, CLIENT_ID, undefined);

async function cachedFetch(url, options) {
    const cached = localStorage.getItem(url);
    if (cached) {
        console.log('Using cached data for:', url);
        return JSON.parse(cached);
    }

    const response = await fetch(url, options);
    const data = await response.json();
    localStorage.setItem(url, JSON.stringify(data));
    return data;
}

// Auth functions remain the same
async function startAuth() {
    const code_verifier = oauth.randomPKCECodeVerifier();
    sessionStorage.setItem('code_verifier', code_verifier);
    const code_challenge = await oauth.calculatePKCECodeChallenge(code_verifier);

    sessionStorage.setItem('code_verifier', code_verifier);

    const authUrl = oauth.buildAuthorizationUrl(config, {
        response_type: 'code',
        scope: 'heartrate',
        code_challenge,
        code_challenge_method: 'S256',
        redirect_uri: REDIRECT_URI
    });
    window.location.href = authUrl.href;
}

async function handleCallback() {
    const code_verifier = sessionStorage.getItem('code_verifier');
    if (!code_verifier) {
        throw new Error('No code_verifier found in session storage');
    }

    const currentUrl = new URL(window.location.href);

    try {
        const tokens = await oauth.authorizationCodeGrant(
            config,
            currentUrl,
            { pkceCodeVerifier: code_verifier }
        );

        sessionStorage.setItem('access_token', tokens.access_token);
        sessionStorage.removeItem('code_verifier');
        window.history.pushState({}, document.title, '/');
        await displayAllData();
    } catch (error) {
        console.error('Auth error:', error);
        throw error;
    }
}

async function fetchStat(stat, year, month) {
    const accessToken = sessionStorage.getItem('access_token');
    if (!accessToken) {
        throw new Error('No access token found');
    }
    let lastDay = new Date(year, month, 0).getDate();
    // if it's the current month, make last day today
    if (year === new Date().getFullYear() && month === new Date().getMonth() + 1) {
        lastDay = new Date().getDate().toString().padStart(2, '0');
    }
    const url = `https://api.fitbit.com/1/user/-/${stat}/date/${year}-${month.toString().padStart(2, '0')}-01/${year}-${month.toString().padStart(2, '0')}-${lastDay}.json`;

    const data = await cachedFetch(url, {
        headers: { Authorization: `Bearer ${accessToken}` }
    });
    return data;
}

async function fetchHRV(year, month) {
    const data = await fetchStat('hrv', year, month);
    return data.hrv.map((item, index) => ({
        date: `${year}-${month.toString().padStart(2, '0')}-${(index + 1).toString().padStart(2, '0')}`,
        value: item.value.deepRmssd
    }));
}

async function fetchHeartRate(year, month) {
    const data = await fetchStat('activities/heart', year, month);
    return data['activities-heart'].map(item => ({
        date: item.dateTime,
        value: item.value.restingHeartRate
    })).filter(item => item.value !== undefined);  // Filter out days with no resting heart rate
}

// Get last three months helper
function getLastMonths(numMonths) {
    const now = new Date();
    const currentMonth = now.getMonth() + 1;
    const currentYear = now.getFullYear();

    const months = [];
    for (let i = 0; i < numMonths; i++) {
        let month = currentMonth - i;
        let year = currentYear;
        if (month <= 0) {
            month += 12;
            year -= 1;
        }
        months.push({ year, month });
    }
    return months;
}

// Display functions
function createChart(data, elementId, label, color, yScale) {
    new Chart(elementId, {
        type: 'line',
        data: {
            labels: data.map(item => item.date),
            datasets: [{
                label: label,
                data: data.map(item => item.value),
                borderColor: color,
                tension: 0.1
            }]
        },
        options: {
            scales: yScale,
            responsive: true,
            maintainAspectRatio: false
        }
    });
}

async function displayAllData() {
    const months = getLastMonths(6);

        const hrvResults = await Promise.all(
            months.map(({ year, month }) => fetchHRV(year, month))
        );
        const hrvData = hrvResults.flat().sort((a, b) =>
            new Date(a.date) - new Date(b.date)
        );

        // Fetch Heart Rate data
        const heartRateResults = await Promise.all(
            months.map(({ year, month }) => fetchHeartRate(year, month))
        );
        const heartRateData = heartRateResults.flat().sort((a, b) =>
            new Date(a.date) - new Date(b.date)
        );

        // Create charts
    createChart(hrvData, 'hrvChart', 'HRV (RMSSD)', 'rgb(75, 192, 192)', {
        y: {
            suggestedMin: 0,
            suggestedMax: 40
        }
    });

    createChart(heartRateData, 'heartRateChart', 'Resting Heart Rate', 'rgb(255, 99, 132)', {
        y: {
            suggestedMin: 50,
            suggestedMax: 90
        }});
}

// Initialize
async function start() {
    if (window.location.search.includes('code=')) {
        await handleCallback();
    } else if (sessionStorage.getItem('access_token')) {
        await displayAllData();
    }
}

window.startAuth = startAuth;
start();
